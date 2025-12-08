use asky::Select;
use color_eyre::{
    Result,
    eyre::{Context, eyre},
};
use ext4_rs::{BLOCK_SIZE, BlockDevice, Ext4};
use glob::glob;
use gpt::partition_types::OperatingSystem::Linux;
use gpt::partition_types::Type;
use std::{path::PathBuf, sync::Arc};
use ziti_api::models::IdentityEnrollmentsOtt;

const SECTOR_SIZE: usize = 512;

#[derive(Debug)]
pub struct DiskImage {
    path: PathBuf,
    partition_offset: usize,
}

impl BlockDevice for DiskImage {
    fn read_offset(&self, mut offset: usize) -> Vec<u8> {
        dbg!(offset);
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
                "Couldn't find any disk images. Make sure that they use the .img file extension and place them in the current-, home- or configuration directory."
            );
            None
        }
        1 => {
            println!("Using disk image {}", paths.first().unwrap().display());
            Some(paths.first().unwrap())
        }
        2.. => {
            let answer = Select::new(
                "Found multiple disk images. Please select the correct one:",
                paths.into_iter().map(|path| path.display().to_string()),
            )
            .prompt()?;
            Some(&PathBuf::from(answer))
        }
    };

    Ok(path.cloned())
}

pub fn create_zitibox_image(enrollment: IdentityEnrollmentsOtt) -> Result<Option<PathBuf>> {
    let image = choose_image();

    if let Ok(Some(path)) = image {
        // Find partition start
        let cfg = gpt::GptConfig::new().writable(false);
        let disk = cfg.open(&path)?;
        let (_, partition) = disk
            .partitions()
            .first_key_value()
            .ok_or(eyre!("Couldn't find a partition in the disk image"))?;

        dbg!(&partition);
        if let Type { os: Linux, .. } = partition.part_type_guid {
            // Write file
            let disk = Arc::new(DiskImage {
                path,
                partition_offset: partition.first_lba as usize,
            });
            let ext4 = Ext4::open(disk);

            // Insert our identity
            for i in 0..10 {
                let path = format!("dirtest{}", i);
                let path = path.as_str();
                let r = ext4.dir_mk(path);
                assert!(r.is_ok(), "dir make error {:?}", r.err());
            }

            let path = "dir1/dir2/dir3/dir4/dir5/dir6";
            let r = ext4.dir_mk(path);
            
            assert!(r.is_ok(), "dir make error {:?}", r.err());
        } else {
            return Err(eyre!(
                "First partition in image does not contain a Linux host"
            ));
        }
    }

    Ok(None)
}
