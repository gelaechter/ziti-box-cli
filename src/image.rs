use color_eyre::{
    Result,
    eyre::{self, Context, eyre},
};
use convert_case::ccase;
use ext4_rs::{BLOCK_SIZE, BlockDevice, Ext4, InodeFileType};
use gpt::partition_types::OperatingSystem::Linux;
use gpt::partition_types::Type;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::{net::IpAddr, path::PathBuf, sync::Arc};

const SECTOR_SIZE: usize = 512;
/// See [`ext4_rs::ext4_defs::direntry::DirEntryType::EXT4_DE_REG_FILE`]\
/// This module is sadly private
const EXT4_DE_REG_FILE: u8 = 1;

#[derive(Debug)]
pub struct DiskImage {
    path: PathBuf,
    partition_offset: usize,
}

impl BlockDevice for DiskImage {
    fn read_offset(&self, mut offset: usize) -> Vec<u8> {
        // Correct our offset, our image has a sector size of
        offset += self.partition_offset * SECTOR_SIZE;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .unwrap();
        let mut buf = vec![0u8; BLOCK_SIZE];
        let _r = file.seek(std::io::SeekFrom::Start(offset as u64));
        let _r = file.read_exact(&mut buf);

        buf
    }

    fn write_offset(&self, mut offset: usize, data: &[u8]) {
        // Correct our offset
        offset += self.partition_offset * SECTOR_SIZE;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .unwrap();

        let _r = file.seek(std::io::SeekFrom::Start(offset as u64));
        let _r = file.write_all(data);
    }
}

/// Wrapper for an Ext4 that signifies this to be a Ziti Box image\
pub struct ZitiBoxImage(Ext4);

impl ZitiBoxImage {
    /// This creates a JWT file inside the /opt/openziti/etc/identities\
    /// The jwt parameter is written as the content of the file
    pub fn write_ziti_jwt(&self, jwt: &str) -> Result<()> {
        let ext4 = &self.0;

        // Get identity directory
        let path = "/opt/openziti/etc/identities/";
        let inode = ext4.ext4_dir_open(path).map_err(|e| {
            eyre!(
                "Couldn't find inode for Ziti identity directory opt/openziti/etc/identities/
            Ensure that the chosen image is a ZitiBox image: {e:#?}"
            )
        })?;

        // Remove old files from identity directory
        for entry in ext4.ext4_dir_get_entries(inode) {
            if entry.get_de_type() == EXT4_DE_REG_FILE {
                ext4.file_remove(&format!("{}{}", path, entry.get_name()))
                    .map_err(|e| {
                        eyre!("Can't remove old files in the Ziti identitiy directory:\n{e:#?}")
                    })?;
            }
        }

        // Create identity file
        let inode_mode = InodeFileType::S_IFREG.bits(); // Inode File REGular
        let jwt_file = ext4
            .create(inode, "identity.jwt", inode_mode)
            .map_err(|e| eyre!("Couldn't create identity file:\n{e:#?}"))?;

        // Write the jwt into the file
        ext4.ext4_file_write(jwt_file.inode_num.into(), 0, jwt.as_bytes())
            .map_err(|e| eyre!("Couldn't write jwt into the disk image:\n{e:#?}"))?;

        Ok(())
    }

    /// This writes an entry into /etc/hosts\
    /// This may be needed for when our controller isn't publicly available.\
    /// **The host parameter is trusted at this stage**, make sure you check it (regex or something)
    pub fn write_hosts_entry(&self, ip: IpAddr, host: &str) -> Result<()> {
        let ext4 = &self.0;

        // Open the file in append mode (O_APPEND: https://man7.org/linux/man-pages/man2/open.2.html)
        let hosts_file = ext4
            .ext4_file_open("/etc/hosts", "a")
            .map_err(|e| eyre!("Couldn't open /etc/hosts in the disk image:\n{e:#?}"))?;

        // The hosts entry should be on the next line
        let entry = format!("\n{ip} {host}");

        // Write the entry into the file
        ext4.ext4_file_write(hosts_file.into(), 0, entry.as_bytes())
            .map_err(|e| eyre!("Couldn't write the hosts entry into the disk image:\n{e:#?}"))?;
        Ok(())
    }

    /// This writes the hostname of the Ziti Box into the /etc/hostname file.\
    /// This is not required for OpenZiti but makes our underlying network less confusing.\
    pub fn write_hostname(&self, hostname: &str) -> Result<()> {
        let ext4 = &self.0;

        // Open / create file
        let hostname_file = ext4
            .ext4_file_open("/etc/hostname", "w")
            .map_err(|e| eyre!("Couldn't open /etc/hostname in the disk image:\n{e:#?}"))?;

        // Sanitize hostname and convert to train case (https://docs.rs/convert_case/latest/convert_case/enum.Case.html#variant.Train)
        let hostname = format!(
            "ZBox-{}",
            ccase!(
                train,
                hostname.chars().filter(char::is_ascii).collect::<String>()
            )
        );

        // Write the hostname into the file
        ext4.ext4_file_write(hostname_file.into(), 0, hostname.as_bytes())
            .map_err(|e| eyre!("Couldn't write the hostname into the disk image:\n{e:#?}"))?;

        Ok(())
    }

    /// Writes two ssh keys for tcpdump and zfw respectively into /home/ziticli/.ssh/authorized_keys
    /// This allows to connect to the zitibox using ssh and checking requests on enp1s0
    /// It also allows us to check applied 
    pub fn write_ssh_keys(&self) -> Result<()> {
        todo!("
        Write any ssh keys onto their respective line
        Be aware that the line will already contain a `command=` directive for the keys command
        ")
    }
}

/// Trys to initialize a Ziti Box from a file path
impl TryFrom<PathBuf> for ZitiBoxImage {
    type Error = eyre::Report;

    fn try_from(path: PathBuf) -> std::result::Result<Self, Self::Error> {
        // Read the partition table and find the start of the first partition
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg.open(&path).wrap_err("Couldn't read a ")?;
        let (_, partition) = disk
            .partitions()
            .first_key_value()
            .ok_or_else(|| eyre!("Couldn't find a partition in the disk image"))?;

        if let Type { os: Linux, .. } = partition.part_type_guid {
            // Open the first partition as an ext4 block device
            let disk = Arc::new(DiskImage {
                path,
                partition_offset: usize::try_from(partition.first_lba).wrap_err("First logical block address doesn't fit into a pointer. Is this a 32-Bit system?")?,
            });
            let ext4 = Ext4::open(disk);
            Ok(Self(ext4))
        } else {
            Err(eyre!(
                "First partition in image does not contain an EXT4 Linux host"
            ))
        }
    }
}
