use color_eyre::{
    Result,
    eyre::{Context, eyre},
};
use dialoguer::Select;
use ext4_rs::{BLOCK_SIZE, BlockDevice, Ext4};
use glob::glob;
use gpt::partition_types::OperatingSystem::Linux;
use gpt::partition_types::Type;
use std::{path::PathBuf, sync::Arc};

use crate::TextColors;

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

        use std::fs::OpenOptions;
        use std::io::{Read, Seek};
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

        use std::fs::OpenOptions;
        use std::io::{Seek, Write};
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .unwrap();

        let _r = file.seek(std::io::SeekFrom::Start(offset as u64));
        let _r = file.write_all(data);
    }
}

pub fn choose_image() -> Result<Option<PathBuf>> {
    // Directories we want to search with a *.img globbing pattern
    let current_dir = std::env::current_dir()?
        .join("*.img")
        .to_str()
        .map(ToString::to_string);

    let home_dir = dirs_next::home_dir()
        .map(|dir| dir.join("*.img"))
        .and_then(|path| path.to_str().map(ToString::to_string));

    let config_dir = dirs_next::config_dir()
        .map(|path| path.join("*.img"))
        .and_then(|path| path.to_str().map(ToString::to_string));

    let mut paths: Vec<PathBuf> = vec![];

    for dir in [current_dir, home_dir, config_dir].into_iter().flatten() {
        // Create glob pattern
        let pattern = glob(&dir).wrap_err("Couldn't build globbing pattern")?;
        // Glob directory and, iterate the glob iter and add successfully globbed files to paths
        let mut files: Vec<PathBuf> = pattern.filter_map(Result::ok).collect();
        paths.append(&mut files);
    }

    let path = match paths.len() {
        0 => {
            println!(
                "{}", "Couldn't find any disk images. Make sure that they use the .img file extension and place them in the current-, home- or configuration directory.".alert()
            );
            None
        }
        1 => {
            println!("Using disk image {}", paths.first().unwrap().display());
            Some(paths.first().unwrap())
        }
        2.. => {
            let answer = Select::new()
                .with_prompt("Found multiple disk images. Please select the correct one:")
                .items(paths.iter().map(|path| path.display().to_string()))
                .interact()?;
            Some(&paths[answer])
        }
    };

    Ok(path.cloned())
}

pub fn create_zitibox_image(jwt: String) -> Result<()> {
    let image = choose_image();

    if let Ok(Some(path)) = image {
        // Read the partition table and find the start of the first partition
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg.open(&path)?;
        let (_, partition) = disk
            .partitions()
            .first_key_value()
            .ok_or(eyre!("Couldn't find a partition in the disk image"))?;

        if let Type { os: Linux, .. } = partition.part_type_guid {
            // Open the first partition as an ext4 block device
            let disk = Arc::new(DiskImage {
                path,
                partition_offset: partition.first_lba as usize,
            });
            let ext4 = Ext4::open(disk);

            write_ziti_jwt(&ext4, jwt)?;
            // TOOD: Should set the hostname based on the
            // write_hostname(&ext4, );
        } else {
            return Err(eyre!(
                "First partition in image does not contain an EXT4 Linux host"
            ));
        }
    }

    Ok(())
}

pub fn write_ziti_jwt(ext4: &Ext4, jwt: String) -> Result<()> {
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
        println!("{}{}", path, entry.get_name());
        ext4.file_remove(&format!("{}{}", path, entry.get_name()))
            .map_err(|e| {
                eyre!("Can't remove old files in the Ziti identitiy directory:\n{e:#?}")
            })?;
    }

    // Create jwt file in identities directory
    let jwt_file = ext4
        .ext4_file_open(&format!("{}identity.jwt", path), "w")
        .map_err(|e| eyre!("Couldn't create the jwt file in the disk image:\n{e:#?}"))?;

    // Write the jwt into the file
    ext4.ext4_file_write(jwt_file.into(), 0, jwt.as_bytes())
        .map_err(|e| eyre!("Couldn't write jwt into the disk image:\n{e:#?}"))?;

    Ok(())
}

pub fn write_hostname(ext4: &Ext4, hostname: String) -> Result<()> {
    let jwt_file = ext4
        .ext4_file_open("/etc/hostname", "w")
        .map_err(|e| eyre!("Couldn't open the hostname file in the disk image:\n{e:#?}"))?;

    // Write the jwt into the file
    ext4.ext4_file_write(jwt_file.into(), 0, hostname.as_bytes())
        .map_err(|e| eyre!("Couldn't write the hostname into the disk image:\n{e:#?}"))?;

    Ok(())
}
