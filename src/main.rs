#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

mod api;
mod config;
mod image;
mod secrets;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{Context, eyre},
    owo_colors::OwoColorize,
};
use comfy_table::Table;
use dialoguer::{Confirm, Input, Password, Select};
use glob::glob;
use reqwest::Url;
use std::{fs, net::IpAddr, path::PathBuf, str::FromStr};
use ziti_api::models::{IdentityEnrollmentsOtt, identity_detail::EdgeRouterConnectionStatus};

use crate::{
    api::{CONFIG_PATH, EnrollmentState, ZitiApi},
    image::ZitiBoxImage,
    secrets::{BasicKeystore, FreeDesktopKeystore},
};

// Define flags
#[derive(Parser, Debug)]
#[command(name = "Ziti Box utility cli")]
#[clap(author, version, about)]
struct Args {
    /// Disables the use of a FreeDesktop Secret Service for environments where it is not available\
    /// Your , PASSWORD and SESSION KEY will then be stored IN PLAINTEXT
    #[arg(long)]
    pub basic_keystore: bool,
    /// Which action to execute
    #[clap(subcommand)]
    pub subcommand: SubCommands,
}

#[derive(Clone, Debug, Subcommand)]
enum SubCommands {
    /// Configure your endpoint and authentication
    Configure,
    /// Lists all Ziti Box identities
    List,
    /// Resets the enrollment of a Ziti Box identity
    ReEnroll {
        #[arg()]
        ziti_box_id: String,
    },
    /// Create a new Ziti Box identity
    Create {
        #[arg()]
        name: String,
    },
    /// Writes a Ziti Box identity into an existing disk image
    Image {
        /// The id of the Ziti Box for which to create an image
        #[arg()]
        ziti_box_id: String,
        /// Optionally lets you define the path to the image
        ///
        /// Without this ZitiBox will look for your image in your home directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Optionally lets you add a hosts entry to the image
        ///
        /// The entry has the format "ip:host", e.g. "192.168.175.3:ziti.box"
        /// This is useful if your controller is not hosted publicly but still requires a hostname
        #[arg(long, value_parser = host_entry_parser)]
        host_entry: Option<HostsEntry>,
    },
    /// Irreversibly deletes a Ziti Box identity
    Delete {
        #[arg()]
        ziti_box_id: String,
    },
}

#[derive(Clone, Debug)]
struct HostsEntry {
    ip: IpAddr,
    host: String,
}

const GLOBAL_KEYRING_SERVICE: &str = "zitibox_cli";

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    keyring::set_global_service_name(GLOBAL_KEYRING_SERVICE);

    cli().await
}

/// This starts the cli
pub async fn cli() -> Result<()> {
    let args = Args::parse();

    // Allow the user to disable using a FreeDesktop Secret Service
    if args.basic_keystore {
        secrets::init_key_store(Box::new(BasicKeystore::new()));
    } else {
        secrets::init_key_store(Box::new(FreeDesktopKeystore::new()));
    }

    match args.subcommand {
        SubCommands::Configure => cmd_first_time_configuration().await,
        SubCommands::List => cmd_list_ziti_boxes().await,
        SubCommands::Image {
            ziti_box_id,
            path,
            host_entry,
        } => cmd_create_img(ziti_box_id, path, host_entry).await,
        SubCommands::ReEnroll { ziti_box_id } => cmd_re_enroll_ziti_box(ziti_box_id).await,
        SubCommands::Create { name } => cmd_create_ziti_box(name).await,
        SubCommands::Delete { ziti_box_id } => cmd_delete_ziti_box(ziti_box_id).await,
    }
}

/// Either loads the existing ZitiApi or starts first time configuration
async fn construct_ziti_api() -> Result<ZitiApi> {
    ZitiApi::load().await?.ok_or_else(|| eyre!(
            "Couldn't find a configuration at {}. Start the first time configuration with the configure command...",
            CONFIG_PATH.display()
        ))
}

/// Lists the ziti boxes on the command line
async fn cmd_list_ziti_boxes() -> Result<()> {
    let ziti_api = construct_ziti_api().await?;
    let identities = ziti_api.list_ziti_boxes().await?;

    if identities.is_empty() {
        println!("{}", "There are no Ziti Box identities to display.".info());
        return Ok(());
    }

    println!("{}", "Listing Ziti Box identities:".info());

    // Build a table from our identities
    let mut table = Table::new();
    table.set_header(vec!["Id", "Status", "Name", "Enrollment"]);

    for zitibox in identities {
        table.add_row(vec![
            zitibox.id,
            match &zitibox.edge_router_connection_status {
                EdgeRouterConnectionStatus::Online => "Online".success().to_string(),
                EdgeRouterConnectionStatus::Offline => "Offline".alert().to_string(),
                EdgeRouterConnectionStatus::Unknown => "Unknown".yellow().to_string(),
            },
            zitibox.name,
            match EnrollmentState::from(&*zitibox.enrollment) {
                EnrollmentState::Enrolled => "Already enrolled".success().to_string(),
                EnrollmentState::Expired => "Enrollment expired".alert().to_string(),
                EnrollmentState::ReadyToEnroll => {
                    let ott = zitibox
                        .enrollment
                        .ott
                        .expect("Implied through ReadyToEnroll");

                    let expiration = pretty_expiration(&ott);

                    match expiration {
                        Some(expires) => format!("Ready to enroll ({expires})"),
                        None => "Ready to enroll".to_string(),
                    }
                    .bright_blue()
                    .to_string()
                }
                EnrollmentState::Unknown => "Unknown enrollment state".yellow().to_string(),
            },
        ]);
    }

    println!("{table}");
    Ok(())
}

/// Creates a disk image for a Ziti Box identity
async fn cmd_create_img(
    ziti_box_id: String,
    path: Option<PathBuf>,
    host_entry: Option<HostsEntry>,
) -> Result<()> {
    let ziti_box = construct_ziti_api()
        .await?
        .get_ziti_box(ziti_box_id.clone())
        .await?;

    // Check if the ZitiBox is ready to enroll
    if !matches!(
        EnrollmentState::from(&*ziti_box.enrollment),
        EnrollmentState::ReadyToEnroll
    ) {
        // If it isn't then offer to reset enrollment
        println!("{}", "This ZitiBox is not ready to be enrolled".alert());
        let reenroll = Confirm::new()
            .with_prompt("Do you want to re-enroll the Ziti Box?".info().to_string())
            .interact()
            .unwrap();

        if reenroll {
            cmd_re_enroll_ziti_box(ziti_box_id).await?;
        }
    }

    // Now the ZitiBox is ready to enroll
    let jwt = ziti_box
        .enrollment
        .ott
        .expect("should be guaranteed through EnrollmentState::ReadyToEnroll")
        .jwt
        .ok_or_else(|| eyre!("Ziti Box identity enrollment didn't contain a JWT"))?;

    // Select an image
    let img_path = match path {
        Some(file_path) => file_path,
        None => choose_image()?.ok_or_else(|| eyre!(
                "{}", "Couldn't find any disk images. Make sure that your image uses the .img file extension and place it somewhere in the home directory.
                Alternatively use the --path option to manually define the image location instead.".alert()
            ))?,
    };

    // Check if a backup of the disk image exists
    let mut backup = img_path.clone();
    backup.set_extension("img.bak");

    if !fs::exists(&backup)? {
        // If not offer to create one
        println!(
            "{}",
            
                "No image backup found. Ziti Box CLI changes images in place, keeping one clean copy in case of write errors is recommended.".info()
        );
        let copy = Confirm::new()
            .with_prompt("Create a backup now?".info().to_string())
            .interact()?;

        if copy {
            tokio::fs::copy(img_path.clone(), backup).await?;

            println!("{}", "Successfully created backup of image.".success());
        }
    }

    println!("{}", "Writing changes to disk image...".info());

    // Try to create a ZitiBox image from the selected disk image
    // This fails if the image does not contain an Ext4 disk partition
    let image = ZitiBoxImage::try_from(img_path)
        .wrap_err("The selected disk image is not a valid Ziti Box image")?;

    // Write JWT, Hostname and optionally a host entry
    image.write_ziti_jwt(jwt)?;
    image.write_hostname(ziti_box.id)?;
    if let Some(host_entry) = host_entry {
        image.write_hosts_entry(host_entry.ip, host_entry.host)?;
    }

    println!(
        "{}",
        "Successfully overwrote wrote identity into disk image".success()
    );

    Ok(())
}

/// Starts the first time configuration dialogue
pub async fn cmd_first_time_configuration() -> Result<()> {
    // Ask for the controller URL
    let url: String = Input::new()
        .with_prompt("Enter controller url (e.g. https://controller.ziti:1280)")
        .with_initial_text("https://")
        .interact_text()?;

    let url = Url::parse(&format!("{url}/edge/management/v1"))?;

    let mut accept_bad_tls = false;

    // Retry if we allow bad tls
    loop {
        // Check if we can connect
        match ZitiApi::try_endpoint(url.clone(), accept_bad_tls).await {
            // Exit retry loop if the connection works
            Ok(_) => {
                println!("{}", "Endpoint is responding".success());
                break;
            }
            Err(api::EndpointError::TLSError) => {
                println!(
                    "{}",
                        "Cannot connect to endpoint, the controller certificate seems to be self-signed.".alert()
                );

                // Ask user to allow bad tls
                accept_bad_tls = Confirm::new()
                    .with_prompt(format!(
                        "{}",
                        "Accept invalid TLS certs? Only allow this if you self signed your certs.".alert()
                    ))
                    .interact()?;
            }

            // If this is a generic error then just error out
            Err(api::EndpointError::Unknown(e)) => {
                println!(
                    "{}",
                        "Cannot connect to endpoint, please make sure you entered the correct URL.".alert()
                );
                return Err(eyre!("Couldn't contact endpoint: {:#?}", e));
            }
        };
    }

    let mut username = String::new();
    let mut password = String::new();

    loop {
        let username_prompt = Input::new()
            .with_prompt("Enter username")
            .with_initial_text(username.clone());

        username = username_prompt.interact_text()?;
        password = Password::new().with_prompt("Enter password").interact()?;

        // Check if we can authenticate
        match ZitiApi::try_authenticate(
            url.clone(),
            accept_bad_tls,
            username.clone(),
            password.clone(),
        )
        .await
        {
            Ok(success) => {
                if success {
                    println!("{}", "Successfully authenticated".success());

                    // If we can then save our configuration
                    ZitiApi::save(url, accept_bad_tls, username, password)
                        .await
                        .wrap_err("Couldn't save the configuration.")?;

                    let msg = format!("Saved configuration to {}", CONFIG_PATH.display());
                    println!("{}", msg.success());
                    return Ok(());
                }
                println!("{}", "The provided credentials are incorrect. Ensure you entered the correct credentials.".alert());
            }
            Err(e) => {
                return Err(e).wrap_err("Error during authentication");
            }
        }
    }
}

pub async fn cmd_re_enroll_ziti_box(ziti_box_id: String) -> Result<()> {
    let ziti_api = construct_ziti_api().await?;
    let ziti_box = ziti_api.get_ziti_box(ziti_box_id.clone()).await?;

    // Check if the ZitiBox is ready to be enrolled
    if matches!(
        EnrollmentState::from(&*ziti_box.enrollment),
        EnrollmentState::Enrolled
    ) && !Confirm::new()
        .with_prompt(
            "Are you sure you want to reset the enrollment for this Ziti Box? 
            You will have to reflash the image!"
                .alert()
                .to_string(),
        )
        .interact()?
    {
        return Ok(());
    }

    ziti_api.reset_enrollment(ziti_box_id).await?;

    println!(
        "{}",
        "Reset enrollment of your Ziti Box. It is now ready to enroll.".success()
    );

    Ok(())
}

async fn cmd_create_ziti_box(name: String) -> Result<()> {
    let ziti_api = construct_ziti_api().await?;

    // Abort if a Ziti Box with this name already exists
    if ziti_api
        .list_ziti_boxes()
        .await?
        .iter()
        .any(|zbox| zbox.name == name)
    {
        return Err(eyre!("A Ziti Box with this name already exists"));
    }

    ziti_api.create_ziti_box(name.clone()).await?;

    let msg = format!("Successfully created Ziti Box identity \"{name}\"");
    println!("{}", msg.success());
    Ok(())
}

async fn cmd_delete_ziti_box(
    ziti_box_id: String,
) -> std::result::Result<(), color_eyre::eyre::Error> {
    let ziti_api = construct_ziti_api().await?;
    let ziti_box = ziti_api.get_ziti_box(ziti_box_id.clone()).await?;

    // Make sure our user actually wants to delete the right Ziti Box by making them retype its name
    let prompt = format!(
        "Are you sure you want to delete Ziti Box \"{}\"? Retype the name to confirm:",
        ziti_box.name
    ).alert().to_string();

    let input: String = Input::new().with_prompt(prompt).interact_text()?;

    if input == ziti_box.name {
        ziti_api.delete_ziti_box(ziti_box_id).await?;
    }

    let prompt = format!("Ziti Box \"{}\" has been deleted", ziti_box.name);
    println!("{}", prompt.success());

    Ok(())
}

async fn cmd_monitor_ziti_box(ziti_box_id: String) -> Result<()> {
    // Run an SSH session with this command:
    // tcpdump -i enp1s0 -l -w - | tshark -l -r - -T json
    // Parse the json, compare the addresses / ports with the rules
    // Show the output in human readable form
    todo!()
}

/// Define wrappers for colors\
/// TODO: The types used here are a crime but i can't be bothered to alias them right now
pub trait TextColors: Sized {
    /// Colors anything that supports displaying (is sized)
    fn alert<'a>(
        &'a self,
    ) -> owo_colors::SupportsColorsDisplay<
        'a,
        Self,
        owo_colors::FgColorDisplay<'a, owo_colors::colors::BrightRed, Self>,
        impl Fn(&'a Self) -> owo_colors::FgColorDisplay<'a, owo_colors::colors::BrightRed, Self> + 'a,
    > {
        self.if_supports_color(owo_colors::Stream::Stdout, |text: &'a Self| text.bright_red())
    }

    fn info<'a>(
        &'a self,
    ) -> owo_colors::SupportsColorsDisplay<
        'a,
        Self,
        owo_colors::FgColorDisplay<'a, owo_colors::colors::Cyan, Self>,
        impl Fn(&'a Self) -> owo_colors::FgColorDisplay<'a, owo_colors::colors::Cyan, Self> + 'a,
    > {
        self.if_supports_color(owo_colors::Stream::Stdout, |text: &'a Self| text.cyan())
    }

    fn success<'a>(
        &'a self,
    ) -> owo_colors::SupportsColorsDisplay<
        'a,
        Self,
        owo_colors::FgColorDisplay<'a, owo_colors::colors::Green, Self>,
        impl Fn(&'a Self) -> owo_colors::FgColorDisplay<'a, owo_colors::colors::Green, Self> + 'a,
    > {
        self.if_supports_color(owo_colors::Stream::Stdout, |text: &'a Self| text.green())
    }
}
impl<D> TextColors for D {}

fn host_entry_parser(s: &str) -> Result<HostsEntry, String> {
    let (ip, host) = s
        .split_once(":")
        .ok_or("The host entry should have the form \"ip:hostname\"")?;
    let ip = IpAddr::from_str(ip).map_err(|_| format!("{ip} is not a valid ip address"))?;
    if !hostname_validator::is_valid(host) {
        return Err(format!("{host} is not a valid hostname"));
    };

    Ok(HostsEntry {
        ip,
        host: host.to_owned(),
    })
}

/// If the OTT has an expiration this will return the remaining time as a pretty printed string\
/// If 30 seconds are left this will yield "30s"\
/// If 30 minutes are left this will yield "30m"
#[must_use]
pub fn pretty_expiration(ott: &IdentityEnrollmentsOtt) -> Option<String> {
    ott.expires_at
        .as_ref()
        .and_then(|exp| exp.parse::<DateTime<Utc>>().ok())
        .map(|exp| exp - Utc::now())
        .map(|duration| {
            let seconds = duration.num_seconds();
            let minutes = seconds / 60;

            if minutes > 0 {
                format!("{minutes}m")
            } else {
                format!("{seconds}s")
            }
        })
}

pub fn choose_image() -> Result<Option<PathBuf>> {
    // Directories we want to search with a *.img globbing pattern
    let home_dir = dirs_next::home_dir().ok_or_else(
        || eyre!("Couldn't find the home directory.\nUse the --path option to manually define the image location instead."))?;
    let glob_path = home_dir
        .join("*.img")
        .into_os_string()
        .into_string()
        .map_err(|os| {
            eyre!(
                "Couldn't convert OsString of globbing path into String:\n{:?}",
                os
            )
        })?;

    // Collect globbed results
    let paths: Vec<PathBuf> = glob(&glob_path)
        .wrap_err("Couldn't build globbing pattern")?
        .filter_map(Result::ok)
        .collect();

    let path = match paths.len() {
        0 => None,
        1 => {
            println!("Using only disk image {}", paths.first().expect("Guaranteed by len=1 match").display());
            Some(paths.first().expect("Guaranteed through len == 1 check"))
        }
        2.. => {
            let answer = Select::new()
                .with_prompt("Found multiple disk images, choose one".info().to_string())
                .items(paths.iter().map(|path| path.display().to_string()))
                .interact()?;
            Some(&paths[answer])
        }
    };

    Ok(path.cloned())
}
