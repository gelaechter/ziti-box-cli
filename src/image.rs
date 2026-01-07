//! This module contains all the logic to write data to a Ziti Box Disk Image
//!
//! To do this we read the raw data in the disk image using the filesystem and treat it as a block device
//! This way image modificatoin should be OS agnostic and be possible without root/administrator priviledges since we're not actually mounting anything.

use color_eyre::{
    Result,
    eyre::{self, Context, eyre},
};
use ext4_rs::{BLOCK_SIZE, BlockDevice, Errno, Ext4, InodeFileType};
use gpt::partition_types::OperatingSystem::Linux;
use gpt::partition_types::Type;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::{net::IpAddr, path::PathBuf, sync::Arc};

const SECTOR_SIZE: usize = 512;

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

/// Inode Newtype
struct Inode(u32);

impl ZitiBoxImage {
    /// Will either open or create the file at path (path from root)
    /// Returns the inode of this file
    fn open_file(&self, path: &str) -> Result<Inode> {
        let mut root_inode = 2;
        let inode_mode = InodeFileType::S_IFREG.bits();
        let file_inode = &self
            .0
            .generic_open(path, &mut root_inode, true, inode_mode, &mut 0)
            .map_err(|e| eyre!("Couldn't get/create identity file inode:\n{e:#?}"))?;

        Ok(Inode(*file_inode))
    }

    fn write_file(&self, inode: &Inode, data: &impl ToString) -> Result<()> {
        self.write_file_offset(inode, 0, data)
    }

    /// Writes into a file
    fn write_file_offset(&self, inode: &Inode, offset: usize, data: &impl ToString) -> Result<()> {
        let binding = data.to_string();
        let data = binding.as_bytes();
        let bytes_written = self
            .0
            .write_at(inode.0, offset, data)
            .map_err(|e| eyre!("Couldn't write into the disk image:\n{e:#?}"))?;

        let data_len = data.len();
        if bytes_written != data_len {
            return Err(eyre!(
                "Didn't write all of the provided data! Wrote {bytes_written} of {data_len} bytes."
            ));
        }

        Ok(())
    }

    /// Reads an entire file and returns the contents
    fn read_file(&self, inode: &Inode) -> Result<Vec<u8>> {
        let ext4 = &self.0;

        let inode_ref = ext4.get_inode_ref(inode.0);
        let file_bytes = usize::try_from(inode_ref.inode.size()).wrap_err(
            "Couldn't create a buffer large enough for file size. Is this a 32-Bit system?",
        )?;
        let mut read_buffer = vec![0u8; file_bytes];

        let bytes_read = ext4
            .read_at(inode.0, 0, &mut read_buffer)
            .map_err(|e| eyre!("Couldn't write into the disk image:\n{e:#?}"))?;

        if bytes_read != file_bytes {
            return Err(eyre!(
                "Didn't read all of the files data! Read {bytes_read} of {file_bytes} bytes."
            ));
        }

        Ok(read_buffer)
    }

    /// Checks if a file exists
    fn file_exists(&self, path: &str) -> Result<bool> {
        let mut root_inode = 2;
        let inode_mode = InodeFileType::S_IFREG.bits();
        let file_inode = self
            .0
            .generic_open(path, &mut root_inode, false, inode_mode, &mut 0);

        match file_inode {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.error() == Errno::ENOENT {
                    Ok(false)
                } else {
                    Err(eyre!("Couldn't check if file exists"))
                }
            }
        }
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        self.0
            .file_remove(path)
            .map_err(|_| eyre!("Couldn't remove error"))
            .and_then(|r| {
                if r == 0 {
                    Ok(())
                } else {
                    Err(eyre!("Couldn't remove error"))
                }
            })
    }

    /// This creates a JWT file inside the /opt/openziti/etc/identities\
    /// The jwt parameter is written as the content of the file
    pub fn write_ziti_jwt(&self, jwt: &str) -> Result<()> {
        let path = "/opt/openziti/etc/identities/identity.jwt";

        // Write the jwt into the file
        let jwt_inode = self.open_file(path)?;
        self.write_file(&jwt_inode, &jwt.to_owned())?;

        Ok(())
    }

    /// This writes an entry into /etc/hosts\
    /// This may be needed for when our controller isn't publicly available.\
    /// **The host parameter is trusted at this stage**, make sure you check it (regex or something)
    pub fn write_hosts_entry(&self, ip: IpAddr, host: &str) -> Result<()> {
        let hosts_path = "/etc/hosts";
        let backup_path = "/etc/hosts.bak";

        // We might have to recover a backup if we want to start from a clean state
        // this is because we change the image in place and not copy it
        // Otherwise we would accumulate more and more hosts entries which we don't want
        let (hosts_file, hosts_contents) = if self.file_exists(backup_path)? {
            // If a backup exists restore that
            self.remove_file(hosts_path)?;
            let backup = self.open_file(backup_path)?;
            let contents = String::from_utf8(self.read_file(&backup)?)?;

            let hosts_file = self.open_file(hosts_path)?;
            self.write_file(&hosts_file, &contents)?;

            (hosts_file, contents) // return the created hosts file and its contents
        } else {
            // If no backup exists create one
            let hosts_file = self.open_file(hosts_path)?;
            let contents = String::from_utf8(self.read_file(&hosts_file)?)?;

            let backup = self.open_file(backup_path)?;
            self.write_file(&backup, &contents)?;

            (hosts_file, contents) // return the original hosts file and its contens
        };

        let entry = format!("\n# Ziti Box CLI\n{ip} {host}");
        self.write_file_offset(&hosts_file, hosts_contents.len(), &entry)?;

        Ok(())
    }

    /// This writes the hostname of the Ziti Box into the /etc/hostname file.\
    /// This is not required for OpenZiti but makes our underlying network less confusing.\
    pub fn write_hostname(&self, hostname: &str) -> Result<()> {
        let path = "/etc/hostname";

        // Clear file
        if self.file_exists(path)? {
            self.remove_file(path)?;
        }

        // Write the hostname into the file
        let hostname_inode = self.open_file(path)?;
        self.write_file(&hostname_inode, &hostname.to_owned())?;

        Ok(())
    }

    /// Writes two ssh keys for tcpdump and zfw respectively into /home/ziticli/.ssh/authorized_keys
    /// This allows to connect to the zitibox using ssh and checking requests on enp1s0
    /// It also allows us to check applied
    pub fn write_ssh_keys(&self) -> Result<()> {
        todo!(
            "
        Write any ssh keys onto their respective line
        Be aware that the line will already contain a `command=` directive for the keys command
        "
        )
    }
}

/// Trys to initialize a Ziti Box from a file path
impl TryFrom<PathBuf> for ZitiBoxImage {
    type Error = eyre::Report;

    fn try_from(path: PathBuf) -> std::result::Result<Self, Self::Error> {
        // Read the partition table and find the start of the first partition
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg
            .open(&path)
            .wrap_err("Couldn't read GPT Table of disk image. Is it a Ziti Box image?")?;
        let (_, partition) = disk.partitions().first_key_value().ok_or_else(|| {
            eyre!("Couldn't find a partition in the disk image. Is it a Ziti Box image?")
        })?;

        if let Type { os: Linux, .. } = partition.part_type_guid {
            // Open the first partition as an ext4 block device
            let disk = Arc::new(DiskImage {
                path,
                partition_offset: usize::try_from(partition.first_lba).wrap_err(
                    "First logical block address doesn't fit into usize. Is this a 32-Bit system?",
                )?,
            });
            let ext4 = Ext4::open(disk);
            Ok(Self(ext4))
        } else {
            Err(eyre!(
                "First partition in disk image does not contain an EXT4 Linux host. Is it a Ziti Box image?"
            ))
        }
    }
}
