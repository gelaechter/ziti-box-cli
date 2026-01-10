//! This module contains all the logic to write data to a Ziti Box Disk Image
//!
//! To do this we read the raw data in the disk image using the filesystem and treat it as a block device
//! This way image modification should be OS agnostic and be possible without root/administrator priviledges since we're not actually mounting anything.
//! 
//! ## Issues
//! 
//! The used crate ext4_rs mostly works. It can however corrupt the filesystem if lesser tested functions are used.
//! Tested and verified functions include:
//!     - [`Ext4::generic_open`]
//!     - [`Ext4::read_at`]
//! 
//! ## Alternative
//! 
//! Alternatively we could also just use a unix loop device to mount the disk image as a directory.
//! Then we could operate normally on it. This does however restrict ZBC to usage on unix devices AND require root.

use color_eyre::{
    Result,
    eyre::{self, Context, eyre},
};
use ext4_rs::{BLOCK_SIZE, BlockDevice, Errno, Ext4, InodeFileType};
use gpt::partition_types::OperatingSystem::Linux;
use gpt::partition_types::Type;
use log::{debug, trace};
use std::io::{Read, Seek, Write};
use std::{fs::OpenOptions, sync::Mutex};
use std::{net::IpAddr, path::PathBuf, sync::Arc};

const SECTOR_SIZE: usize = 512;
const ROOT_INODE: u32 = 2;

#[derive(Debug)]
pub struct DiskImage {
    /// A handle to the file we want to work with
    /// We use a Mutex for its interior mutability since [`BlockDevice`] doesn't allow `&mut self`
    file: Mutex<std::fs::File>,
    /// The offset of our host EXT4 partition
    host_partition_offset: usize,
}

impl DiskImage {
    pub fn new(path: PathBuf, host_partition_offset: usize) -> Result<Self> {
        // Open the file in read/write mode
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .wrap_err("Couldn't open disk image in r/w mode")?;
        let file = Mutex::new(file);

        Ok(Self {
            file,
            host_partition_offset,
        })
    }
}

impl BlockDevice for DiskImage {
    fn read_offset(&self, mut offset: usize) -> Vec<u8> {
        // Correct our offset, our image has a sector size of
        offset += self.host_partition_offset * SECTOR_SIZE;

        let mut buf = vec![0u8; BLOCK_SIZE];
        let mut file = self.file.lock().unwrap();

        // We allow failing quietly as is typical for a block device
        let _r = file.seek(std::io::SeekFrom::Start(offset as u64));
        let _r = file.read_exact(&mut buf);

        buf
    }

    fn write_offset(&self, mut offset: usize, data: &[u8]) {
        // Correct our offset
        offset += self.host_partition_offset * SECTOR_SIZE;

        let mut file = self.file.lock().unwrap();

        // We allow failing quietly as is typical for a block device
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
        trace!("Opening file {path}");

        let inode_mode = InodeFileType::S_IFREG.bits();
        #[allow(const_item_mutation)]
        let file_inode = &self
            .0
            .generic_open(path, &mut ROOT_INODE, true, inode_mode, &mut 0)
            .map_err(|e| eyre!("Couldn't get/create identity file inode:\n{e:#?}"))?;

        trace!("Opened file {path} ({file_inode})");
        Ok(Inode(*file_inode))
    }

    fn write_file(&self, inode: &Inode, data: &impl ToString) -> Result<()> {
        self.write_file_offset(inode, 0, data)
    }

    /// Writes into a file
    fn write_file_offset(&self, inode: &Inode, offset: usize, data: &impl ToString) -> Result<()> {
        trace!("Writing data to file {}: {}", inode.0, data.to_string());

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
        trace!("Reading file ({})", inode.0);
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
        trace!("Checking if file at {path} exists");

        let inode_mode = InodeFileType::S_IFREG.bits();
        let result = self
            .0
            .generic_open(path, &mut ROOT_INODE, false, inode_mode, &mut 0);

        match result {
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
        trace!("Removing file at {path}");

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
        debug!("Writing JWT to Ziti Box image");

        let path = "/opt/openziti/etc/identities/identity.jwt";
        let file_contents = format!("{jwt}\n");

        // Write the jwt into the file
        let jwt_inode = self.open_file(path)?;
        self.write_file(&jwt_inode, &file_contents)?;

        Ok(())
    }

    /// This writes an entry into /etc/hosts\
    /// This may be needed for when our controller isn't publicly available.\
    /// **The host parameter is trusted at this stage**, make sure you check it (regex or something)
    pub fn write_hosts_entry(&self, ip: IpAddr, host: &str) -> Result<()> {
        debug!("Writing hosts entry to Ziti Box Image");
        let hosts_path = "/etc/hosts";
        let backup_path = "/etc/hosts.bak";

        // We might have to recover a backup if we want to start from a clean state
        // this is because we change the image in place and not copy it
        // Otherwise we would accumulate more and more hosts entries which we don't want
        let (hosts_file, hosts_contents) = if self.file_exists(backup_path)? {
            debug!("Restoring hosts backup");

            // If a backup exists restore that
            self.remove_file(hosts_path)?;
            let backup = self.open_file(backup_path)?;
            let contents = String::from_utf8(self.read_file(&backup)?)?;

            let hosts_file = self.open_file(hosts_path)?;
            self.write_file(&hosts_file, &contents)?;

            (hosts_file, contents) // return the created hosts file and its contents
        } else {
            debug!("Creating hosts backup");

            // If no backup exists create one
            let hosts_file = self.open_file(hosts_path)?;
            let contents = String::from_utf8(self.read_file(&hosts_file)?)?;

            let backup = self.open_file(backup_path)?;
            self.write_file(&backup, &contents)?;

            (hosts_file, contents) // return the original hosts file and its contens
        };

        debug!("Inserting hosts entry");
        let file_addition = format!("\n# Ziti Box CLI\n{ip} {host}\n");
        self.write_file_offset(&hosts_file, hosts_contents.len(), &file_addition)?;

        Ok(())
    }

    /// This writes the hostname of the Ziti Box into the /etc/hostname file.\
    /// This is not required for OpenZiti but makes our underlying network less confusing.
    pub fn write_hostname(&self, hostname: &str) -> Result<()> {
        debug!("Writing hostname to Ziti Box image");

        let path = "/etc/hostname";
        let file_contents = format!("{hostname}\n");

        // Clear file
        if self.file_exists(path)? {
            self.remove_file(path)?;
        }

        // Write the hostname into the file
        let hostname_inode = self.open_file(path)?;
        self.write_file(&hostname_inode, &file_contents)?;

        Ok(())
    }

    /// Writes two ssh keys for tcpdump and zfw respectively into /home/ziticli/.ssh/authorized_keys
    /// This allows to connect to the zitibox using ssh and checking requests on enp1s0
    /// It also allows us to check applied
    pub fn write_ssh_keys(&self) -> Result<()> {
        todo!(
            "Write any ssh keys onto their respective line\n\
            Be aware that the line will already contain a `command=` directive for the keys command"
        )
    }
}

/// Trys to initialize a Ziti Box from a file path
impl TryFrom<PathBuf> for ZitiBoxImage {
    type Error = eyre::Report;

    fn try_from(path: PathBuf) -> std::result::Result<Self, Self::Error> {
        debug!(
            "Trying to construct ZitiBoxImage from file at {}",
            path.display()
        );

        // Read the partition table
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg
            .open(&path)
            .wrap_err("Couldn't read GPT table of disk image. Is it a Ziti Box image?")?;

        // Find the first linux partition
        let (_, partition) = disk
            .partitions()
            .iter()
            .find(|(_, partition)| matches!(partition.part_type_guid, Type { os: Linux, .. }))
            .ok_or_else(|| {
                eyre!(
                    "Can't find a Linux host partition in the disk image. Is it a Ziti Box image?"
                )
            })?;

        // Open the linux partition as a block device
        let disk = Arc::new(DiskImage::new(
            path,
            usize::try_from(partition.first_lba).wrap_err(
                "First logical block address doesn't fit into usize. Is this a 32-Bit system?",
            )?,
        )?);

        // Open the block device as an ext4 partition
        let ext4 = Ext4::open(disk);
        Ok(Self(ext4))
    }
}

// =========================== Tests ===============================
// I created these for debugging https://github.com/yuoo655/ext4_rs/issues/10

pub fn image() -> ZitiBoxImage {
    let image_path = PathBuf::from("/home/samuel/ZitiBox.img");
    ZitiBoxImage::try_from(image_path).unwrap()
}

#[test]
fn write_jwt() {
    let image = image();

    let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5YzY0MzM0MmQ5NGY4YTM3MmNlMDNiNzQzODFjNjg4OGMwNmY1ZjkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3ppdGkucG9tbWVyLmluZm86MTI4MCIsInN1YiI6Ii1GNjhrTlVvOCIsImF1ZCI6WyIiXSwiZXhwIjoxNzY3NzU0MDc0LCJqdGkiOiIwM2M3NmE3NS1hZmJiLTQ1MmMtOWE2Ny0yODU4MmM5NjE0MWMiLCJlbSI6Im90dCIsImN0cmxzIjpbInRsczp6aXRpLnBvbW1lci5pbmZvOjEyODAiXX0.DSR3DUXUAsfJ7VMpLlsxyk5wjZkSQms9smM990Nu3--iS3zLb9AmpaWR4-JOIjtvImzWdoyvLmE4TO4k5vwMM92mjaYGRG3i3QECpcgflWZowPXlZC3hF2B2TgSHjvDLCT3Sdixg_7TbNmrnoqETy3pCrPK3_EWyN52b5gwDmYDsGCIfePRqisF51W6NdKZzLD9KQaRE8sN8jhVnwPxrQF53DNBwuGk-n2BsMwGQulCCk1iLiRGMQ8xIDRCWTHMZkfjQYknUKkFFFRxbfsw-JEsnN-N5Yj_fxsOJO1evf1hOSjA6N65iEj5LZDj6vpAQUV1h9uj72Ma_-tJ3THMb4bMgI-EaUNUdD-PflqSejcKjzzy8HhntWQYNAR-Au8oFeu13kRsJG4wEYvEoKSpv5RsXfgNP3ykv97YklwKgMuvLoUlnlxU8OHKn_E-bPEEJRhGByEHvjJjzda4XJwDNFLyvtdFJtMp1JjQQ12vVd9ou3dXLdM-fKDTs_ak_cI8_lhmZg52c71XVmLcRfzucWoF9KPvb6IqRgYCkjFQrAzmnX12BX6w92tVo2fvPiGxuPc_wWvrw4MBoaDgEOiK4zbxFAHzu5y_LsjqjMiu6tGKqUxU7e4Vz9zb67simLmiTHiy1g_ozWttXzUR8tEIb9T1Yfnw0Z8JduNb-oaZLmys";

    image.write_ziti_jwt(jwt).unwrap();
}

#[test]
fn write_hostname() {
    let image = image();

    let hostname = "ZBox-Test-Box-A";

    image.write_hostname(hostname).unwrap();
}

#[test]
fn write_hosts_entry() {
    let image = image();

    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 175, 2));
    let host = "ziti.box";

    image.write_hosts_entry(ip, host).unwrap();
}
