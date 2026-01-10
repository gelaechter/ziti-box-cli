#![feature(type_alias_impl_trait)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]

//! This main module contains the CLI logic
//!
//! In theory this module should be completely replaceable by any other interface should a CLI not be enough

mod api;
mod config;
mod image;
mod secrets;
mod ssh;

use clap::{ArgAction, Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{Context, eyre},
    owo_colors::OwoColorize,
};
use comfy_table::Table;
use convert_case::ccase;
use dialoguer::{Confirm, Input, Password, Select};
use glob::glob;
use log::LevelFilter;
use owo_colors::{
    FgColorDisplay, SupportsColorsDisplay,
    colors::{BrightRed, Cyan, Green},
};
use reqwest::Url;
use std::{fs, net::IpAddr, path::PathBuf, str::FromStr};
use ziti_api::models::identity_detail::EdgeRouterConnectionStatus;

use crate::{
    api::{CONFIG_PATH, EnrollmentState, Port, ZitiApi, ZitiApiError, ZitiConfig},
    image::ZitiBoxImage,
    secrets::KeyStore,
};

// Define flags
#[derive(Parser, Debug)]
#[command(name = "Ziti Box utility cli")]
#[clap(author, version, about)]
struct Args {
    /// Disables the FreeDesktop Secret Service; Your password will be stored STORED IN PLAINTEXT
    ///
    /// This option stores your password and session key in plaintext
    /// It exists for environments where no FreeDesktop Secret Service is available.
    /// Only activate this if there is no way to install a provider like GNOME Keyring or KDE Wallet
    #[arg(long)]
    pub basic_keystore: bool,
    /// Increase verbosity (repeat for more: -v info, -vv debug, -vvv trace)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
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
        #[arg(long, value_parser = parse_host_entry)]
        hosts_entry: Option<HostsEntry>,
    },
    /// Irreversibly deletes a Ziti Box identity
    Delete {
        #[arg()]
        ziti_box_id: String,
    },
    /// Whitelists an internet address and ports
    Whitelist {
        /// The id of the Ziti Box for which to whitelist the address
        #[arg()]
        ziti_box_id: String,
        /// The address to whitelist
        ///
        /// This address supports wildcards, e.g. *.google.com
        #[arg(long_help)]
        address: String,
        /// The ports for which the whitelist counts
        ///
        /// Multiple ports can be entered sepearted by a space (80 433)
        /// Port ranges can be defined using a minus (1000-1005)
        /// This syntax can be used together
        #[arg(num_args = 1.., required = true, value_name = "PORT(S)", value_parser = parse_port)]
        ports: Vec<Port>,
    },
}

#[derive(Clone, Debug)]
struct HostsEntry {
    ip: IpAddr,
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    cli().await
}

/// This starts the cli
pub async fn cli() -> Result<()> {
    let args = Args::parse();

    // Set logger verbosity
    env_logger::Builder::new()
        .filter_level(match args.verbose {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .init();

    // Allow the user to disable using a FreeDesktop Secret Service
    let key_store: KeyStore = if args.basic_keystore {
        KeyStore::basic()
    } else {
        let keystore: Result<KeyStore> = KeyStore::freedesktop().await;
        keystore.wrap_err("Couldn't access FreeDesktop Secret Service. If you are unable to provide a Secret Service use the --basic-keystore option.")?
    };
    secrets::init_key_store(key_store);

    match args.subcommand {
        SubCommands::Configure => cmd_first_time_configuration().await,
        SubCommands::List => cmd_list_ziti_boxes().await,
        SubCommands::Image {
            ziti_box_id,
            path,
            hosts_entry,
        } => cmd_image(ziti_box_id, path, hosts_entry).await,
        SubCommands::ReEnroll { ziti_box_id } => cmd_re_enroll_ziti_box(ziti_box_id).await,
        SubCommands::Create { name } => cmd_create_ziti_box(name).await,
        SubCommands::Delete { ziti_box_id } => cmd_delete_ziti_box(ziti_box_id).await,
        SubCommands::Whitelist {
            ziti_box_id,
            address,
            ports,
        } => cmd_whitelist_address(ziti_box_id, address, ports).await,
    }
}

/// Either loads the existing ZitiApi or starts first time configuration
async fn construct_ziti_api() -> Result<ZitiApi> {
    // Try loading ZitiConfig
    let ziti_conf = ZitiConfig::load().await.wrap_err(eyre!(
        "Error while trying to load config at {}",
        CONFIG_PATH.display()
    ))?;

    // If it doesnt exist run first time configuration instead
    let Some(ziti_conf) = ziti_conf else {
        println!("{}", "It seems Ziti Box CLI has not been configured yet. Starting first time configuration...".info());
        return first_time_configuration().await; // early return
    };

    // If it does then check if we have a valid session token
    let ziti_api = ZitiApi::try_from_session(&ziti_conf)
        .await
        .wrap_err("Error while trying to reuse OpenZiti session")?;

    // If we do use that
    if let Some(api) = ziti_api {
        return Ok(api); // early return
    }

    // Otherwise prompt the user to authenticate again
    let mut prompt = format!(
        "The OpenZiti Session is not valid anymore, please re-enter your password for user {}",
        &ziti_conf.username
    )
    .info()
    .to_string();

    let ziti_api = loop {
        let password = dialoguer::Password::new().with_prompt(prompt).interact()?;

        match ZitiApi::authenticate(&ziti_conf, password).await {
            Ok(api) => break api,
            Err(ZitiApiError::IncorrectCredentials) => {
                prompt = "The entered credentials are incorrect, please retry"
                    .alert()
                    .to_string();
            }
            Err(e) => return Err(e).context("Error during authentication"),
        }
    };

    println!("{}", "Successfully authenticated session".success());

    // Store the new session token
    ziti_api.store_session_token().await?;

    Ok(ziti_api)
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
        // FIXME: Currently doesn't work because of: https://github.com/openziti/ziti/issues/3481
        // let services = ziti_api.list_identity_services(&zitibox.id)
        //     .await?
        //     .into_iter()
        //     .map(|service| format!("{}, ({})", service.name, service.id))
        //     .collect::<Vec<String>>()
        //     .join("\n");

        table.add_row(vec![
            zitibox.id,
            match &zitibox.edge_router_connection_status {
                EdgeRouterConnectionStatus::Online => "Online".success().to_string(),
                EdgeRouterConnectionStatus::Offline => "Offline".alert().to_string(),
                EdgeRouterConnectionStatus::Unknown => "Unknown".info().to_string(),
            },
            zitibox.name,
            match EnrollmentState::from(&*zitibox.enrollment) {
                EnrollmentState::Enrolled => "Already enrolled".success().to_string(),
                EnrollmentState::Expired => "Enrollment expired".alert().to_string(),
                EnrollmentState::ReadyToEnroll { minutes_left } => {
                    format!("Ready to enroll ({minutes_left}m)")
                        .info()
                        .to_string()
                }
                EnrollmentState::Unknown => "Unknown enrollment state".alert().to_string(),
            },
            // services
        ]);
    }

    println!("{table}");
    Ok(())
}

/// Creates a disk image for a Ziti Box identity
async fn cmd_image(
    ziti_box_id: String,
    path: Option<PathBuf>,
    host_entry: Option<HostsEntry>,
) -> Result<()> {
    let ziti_api = construct_ziti_api().await?;
    let mut ziti_box = ziti_api.get_ziti_box(ziti_box_id.clone()).await?;

    // Check if the Ziti Box is ready to enroll
    let prompt = match EnrollmentState::from(&*ziti_box.enrollment) {
        // About to expire
        EnrollmentState::ReadyToEnroll { minutes_left } if minutes_left < 5 => Some(format!(
            "The enrollment of Ziti Box \"{}\" is about to expire.",
            ziti_box.name
        )),
        // Ready to enroll
        EnrollmentState::ReadyToEnroll { .. } => None,
        // Everything else
        _ => Some(format!(
            "Ziti Box \"{}\" is not ready to be enrolled.",
            ziti_box.name
        )),
    };

    if let Some(prompt) = prompt {
        // The Ziti Box is not ready to be enrolled, so offer to re-enroll
        println!("{}", prompt.info());
        if Confirm::new()
            .with_prompt("Do you want to reset the enrollment of the Ziti Box?".info().to_string())
            .default(false)
            .interact()?
        {
            // Re-enroll it, then fetch the new enrollment
            ziti_api.reset_enrollment(ziti_box_id.clone()).await?;
            ziti_box = ziti_api.get_ziti_box(ziti_box_id).await?;
        } else {
            // Otherwise abort
            println!("{}", "Aborting image creation.".info());
            return Ok(());
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
            .default(true)
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

    // Write JWT
    image.write_ziti_jwt(&jwt)?;

    // Sanitize hostname and convert to train case (https://docs.rs/convert_case/latest/convert_case/enum.Case.html#variant.Train)
    let hostname = format!(
        "ZBox-{}",
        ccase!(
            train,
            &ziti_box
                .name
                .chars()
                .filter(char::is_ascii)
                .collect::<String>()
        )
    );

    // Write Hostname
    // FIXME: Writing the hostname or doing that in combination with the JWT corrupts the image to so much that it becomes unbootable
    // image.write_hostname(&hostname)?;

    // Write Hosts entry
    // if let Some(hosts_entry) = host_entry {
    //     image.write_hosts_entry(hosts_entry.ip, &hosts_entry.host)?;
    // }

    println!(
        "{}",
        "Successfully overwrote identity in the disk image".success()
    );

    Ok(())
}

/// Wrapper returning a unit
pub async fn cmd_first_time_configuration() -> Result<()> {
    first_time_configuration().await?;
    Ok(())
}

/// Starts the first time configuration dialogue
pub async fn first_time_configuration() -> Result<ZitiApi> {
    // Ask for the controller URL
    let url: String = Input::new()
        .with_prompt("Enter controller url (e.g. https://controller.ziti:1280)")
        .with_initial_text("https://")
        .interact_text()?;

    let url = Url::parse(&format!("{url}/edge/management/v1"))?;
    let mut accept_bad_tls = false;

    loop {
        match ZitiApi::try_endpoint(url.clone(), accept_bad_tls).await {
            // Exit retry loop if the connection works
            Ok(()) => {
                println!("{}", "Endpoint is responding".success());
                break;
            }
            Err(ZitiApiError::SelfSignedTLS) => {
                println!(
                    "{}",
                    "The controller certificate seems to be self-signed.".alert()
                );

                // Ask user to allow bad tls
                accept_bad_tls = Confirm::new()
                    .with_prompt(
                        "Accept invalid TLS certs? Only allow this if you self signed your certs."
                            .alert()
                            .to_string(),
                    )
                    .interact()?;
            }

            // If this is a generic error then just error out
            Err(e) => return Err(e).context("Cannot connect to endpoint, is the URL correct?"),
        }
    }

    let mut ziti_conf = ZitiConfig {
        url,
        accept_bad_tls,
        username: String::new(),
    };
    let mut password = String::new();

    // Keep prompting username / password until the correct credentials are entered
    let ziti_api: ZitiApi = loop {
        let username_prompt = Input::new()
            .with_prompt("Enter username".info().to_string())
            .with_initial_text(ziti_conf.username.clone()); // Prefill username if already tried once

        ziti_conf.username = username_prompt.interact_text()?;
        password = Password::new()
            .with_prompt("Enter password".info().to_string())
            .interact()?;

        match ZitiApi::authenticate(&ziti_conf, password).await {
            Ok(api) => break api,
            Err(ZitiApiError::IncorrectCredentials) => {
                println!("{}", "Incorrect credentials, please retry".alert());
            }
            Err(e) => return Err(e).context("Error while trying to authenticate"),
        }
    };

    ziti_conf
        .save()
        .await
        .wrap_err("Couldn't save the configuration")?;
    ziti_api
        .store_session_token()
        .await
        .wrap_err("Couldn't save session token to key store")?;

    println!(
        "{}",
        "Successfully configured; Saved configuration and token.".success()
    );

    Ok(ziti_api)
}

pub async fn cmd_re_enroll_ziti_box(ziti_box_id: String) -> Result<()> {
    let ziti_api = construct_ziti_api().await?;
    let ziti_box = ziti_api.get_ziti_box(ziti_box_id.clone()).await?;

    // Check if the ZitiBox is ready to be enrolled
    if matches!(
        EnrollmentState::from(&*ziti_box.enrollment),
        EnrollmentState::Enrolled
    ) && !Confirm::new() // Warn before re-enrolling an enrolled identity
        .with_prompt(
            "Are you sure you want to reset the enrollment for this Ziti Box?\n\
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
    )
    .alert()
    .to_string();

    let input: String = Input::new().with_prompt(prompt).interact_text()?;

    if input == ziti_box.name {
        ziti_api.delete_ziti_box(ziti_box_id).await?;
    }

    let prompt = format!("Ziti Box \"{}\" has been deleted", ziti_box.name);
    println!("{}", prompt.success());

    Ok(())
}

async fn cmd_whitelist_address(
    ziti_box_id: String,
    address: String,
    ports: Vec<Port>,
) -> Result<()> {
    let ziti_api = construct_ziti_api().await?;
    let edge_routers = ziti_api.list_edge_routers().await?;

    // If there is more than one edge router make the user choose one
    let edge_router = match edge_routers.len() {
        0 => {
            return Err(eyre!(
                "No edge routers found to which the traffic could be routed".alert()
            ));
        }
        1 => edge_routers.first().expect("Guaranteed through len=1"),
        2.. => {
            let answer = Select::new()
                .with_prompt("Found multiple edge routers, choose one".info().to_string())
                .items(
                    edge_routers
                        .iter()
                        .map(|id| format!("{} ({})", id.name, id.id)),
                )
                .interact()?;
            &edge_routers[answer]
        }
    };

    ziti_api
        .create_edge_service(ziti_box_id, address, ports, edge_router)
        .await?;

    println!("{}", "Successfully created new edge service".success());

    Ok(())
}

async fn cmd_monitor_ziti_box(ziti_box_id: String) -> Result<()> {
    // Run an SSH session with this command:
    // tcpdump -i enp1s0 -l -w - | tshark -l -r - -T json
    // Parse the json, compare the addresses / ports with the rules
    // Show the output in human readable form
    todo!()
}

/// Wrappers around [`OwoColorize`] color methods ensure consistent colors\
/// They are only applied if the terminal supports them
/// 
/// # Example
/// ```rust
/// println!("{}", "This worked".success()) // this will appear green in terminals that support it
/// ```
pub trait TextColors: Sized {
    fn alert<'a>(
        &'a self,
    ) -> SupportsColorsDisplay<
        'a,
        Self,
        FgColorDisplay<'a, BrightRed, Self>,
        impl Fn(&'a Self) -> FgColorDisplay<'a, BrightRed, Self> + 'a,
    > {
        self.if_supports_color(owo_colors::Stream::Stdout, |text: &'a Self| {
            text.bright_red()
        })
    }

    fn info<'a>(
        &'a self,
    ) -> SupportsColorsDisplay<
        'a,
        Self,
        FgColorDisplay<'a, Cyan, Self>,
        impl Fn(&'a Self) -> FgColorDisplay<'a, Cyan, Self> + 'a,
    > {
        self.if_supports_color(owo_colors::Stream::Stdout, |text: &'a Self| text.cyan())
    }

    fn success<'a>(
        &'a self,
    ) -> SupportsColorsDisplay<
        'a,
        Self,
        FgColorDisplay<'a, Green, Self>,
        impl Fn(&'a Self) -> FgColorDisplay<'a, Green, Self> + 'a,
    > {
        self.if_supports_color(owo_colors::Stream::Stdout, |text: &'a Self| text.green())
    }
}
impl<D> TextColors for D {}

fn parse_host_entry(s: &str) -> Result<HostsEntry, String> {
    let (ip, host) = s
        .split_once(':')
        .ok_or("The host entry should have the form \"ip:hostname\"")?;

    let ip = IpAddr::from_str(ip).map_err(|_| format!("{ip} is not a valid ip address"))?;

    if !hostname_validator::is_valid(host) {
        return Err(format!("{host} is not a valid hostname"));
    }

    Ok(HostsEntry {
        ip,
        host: host.to_owned(),
    })
}

fn parse_port(s: &str) -> Result<Port, String> {
    // Split at minus for ranges
    let ports: Vec<&str> = s.split('-').collect();
    match ports.len() {
        1 => {
            // No range (Port)
            let port_str = ports[0];
            let port = port_str
                .parse::<u16>()
                .map_err(|_e| format!("\"{port_str}\" is not a valid port"))?;
            Ok(Port::Single(port))
        }
        2 => {
            // Range (PortA-PortB)
            let start_str = ports[0];
            let end_str: &str = ports[1];
            let strart_port = start_str
                .parse::<u16>()
                .map_err(|_e| format!("\"{start_str}\" is not a valid port"))?;
            let end_port = end_str
                .parse::<u16>()
                .map_err(|_e| format!("\"{end_str}\" is not a valid port"))?;
            Ok(Port::Range(strart_port, end_port))
        }
        _ => {
            // Something else entirely
            Err("malformed port entry; refer to the help section".to_string())
        }
    }
}

#[allow(clippy::missing_panics_doc)] // I don't know why clippy complains here, possible panics are guarded by matches
pub fn choose_image() -> Result<Option<PathBuf>> {
    // Directories we want to search with a *.img globbing pattern
    let home_dir = dirs_next::home_dir().ok_or_else(
        || eyre!("Couldn't find the home directory.\nUse the --path option to manually define the image location instead."))?;
    let glob_path = home_dir
        .join("*.img")
        .into_os_string()
        .into_string()
        .map_err(|os| eyre!("Couldn't convert OsString of globbing path into String:\n{os:?}"))?;

    // Collect globbed results
    let paths: Vec<PathBuf> = glob(&glob_path)
        .wrap_err("Couldn't build globbing pattern")?
        .filter_map(Result::ok)
        .collect();

    let path = match paths.len() {
        0 => None,
        1 => {
            let message = format!(
                "Found only disk image {}",
                paths.first().expect("Guaranteed by len=1 match").display()
            );
            println!("{}", message.info());
            // Offer using this single image
            if Confirm::new()
                .with_prompt("Do you wish to use this image".info().to_string())
                .default(false)
                .interact()?
            {
                Some(paths.first().expect("Guaranteed through len == 1 check"))
            } else {
                None
            }
        }
        2.. => {
            let answer = Select::new()
                .with_prompt("Found multiple disk images, choose one".info().to_string())
                .items(paths.iter().map(|path| path.display().to_string()))
                .default(0)
                .interact()?;
            Some(&paths[answer])
        }
    };

    Ok(path.cloned())
}
