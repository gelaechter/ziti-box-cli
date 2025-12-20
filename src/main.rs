mod api;
mod config;
mod image;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{Context, eyre},
    owo_colors::{FgColorDisplay, OwoColorize, colors},
};
use comfy_table::Table;
use dialoguer::{Confirm, Input, Password};
use keyring::set_global_service_name;
use reqwest::Url;
use ziti_api::models::{IdentityEnrollmentsOtt, identity_detail::EdgeRouterConnectionStatus};

use crate::api::{EnrollmentState, ZitiApi};

// Define flags
#[derive(Parser, Debug)]
#[command(name = "Ziti Box utility cli")]
#[clap(author, version, about)]
struct Args {
    #[clap(subcommand)]
    pub subcommand: SubCommands,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SubCommands {
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
    /// Produce an Ziti Box image for a Ziti Box identity
    Image {
        #[arg()]
        ziti_box_id: String,
    },
    /// Irreversibly deletes a Ziti Box identity
    Delete {
        #[arg()] 
        ziti_box_id: String,
    },
}

const GLOBAL_KEYRING_SERVICE: &str = "zitibox_cli";

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    set_global_service_name(GLOBAL_KEYRING_SERVICE);

    cli().await
}

/// This starts the cli
pub async fn cli() -> Result<()> {
    let args = Args::parse();
    match args.subcommand {
        SubCommands::Configure => cmd_first_time_configuration().await,
        SubCommands::List => cmd_list_ziti_boxes().await,
        SubCommands::Image { ziti_box_id } => cmd_create_img(ziti_box_id).await,
        SubCommands::ReEnroll { ziti_box_id } => cmd_re_enroll_ziti_box(ziti_box_id).await,
        SubCommands::Create { name } => cmd_create_ziti_box(name).await,
        SubCommands::Delete { ziti_box_id } => cmd_delete_ziti_box(ziti_box_id).await,
    }
}

/// Either loads the existing ZitiApi or starts first time configuration
async fn construct_ziti_api() -> Result<ZitiApi> {
    if let Some(api) = ZitiApi::load().await? {
        Ok(api)
    } else {
        Err(eyre!(
            "Couldn't find a configuration. Start the first time configuration with the configure command..."
        ))
    }
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
                        Some(expires) => format!("Ready to enroll ({})", expires),
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
async fn cmd_create_img(ziti_box_id: String) -> Result<()> {
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

    if let Some(jwt) = ziti_box
        .enrollment
        .ott
        .expect("should be guaranteed through EnrollmentState::ReadyToEnroll")
        .jwt
    {
        image::create_zitibox_image(jwt)
    } else {
        Err(eyre!("Ziti Box identity enrollment didn't contain a JWT"))
    }
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
                println!("{}", "Cannot connect to endpoint, the controller certificate seems to be self-signed.".alert());

                // Ask user to allow bad tls
                accept_bad_tls = Confirm::new()
                    .with_prompt(format!(
                        "{}",
                        "Accept invalid TLS certs? Only allow this if you self signed your certs."
                            .alert()
                    ))
                    .interact()?;
            }

            // If this is a generic error then just error out
            Err(api::EndpointError::Unknown(e)) => {
                println!(
                    "{}",
                    "Cannot connect to endpoint, please make sure you entered the correct URL."
                        .alert()
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
                    // If we can then save our configuration
                    let _ = ZitiApi::save(url, accept_bad_tls, username, password).await;
                    return Ok(());
                } else {
                    println!("{}", "The provided credentials are incorrect. Ensure you entered the correct credentials.".alert())
                }
            }
            Err(e) => {
                return Err(e).wrap_err("Error during authentication");
            }
        };
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

    let msg = format!("Successfully created Ziti Box identity \"{}\"", name);
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

    let prompt = format!("Ziti Box \"{}\" has been deleted", ziti_box.name)
        .success()
        .to_string();
    println!("{}", prompt);

    Ok(())
}

/// Define wrappers for colors
/// TODO: consider changing each functions return type to [String] by enforcing [std::fmt::Display] and calling [Display::to_string()]
pub trait TextColors: Sized {
    fn alert(&self) -> FgColorDisplay<'_, colors::BrightRed, Self> {
        self.bright_red()
    }

    fn info(&self) -> FgColorDisplay<'_, colors::Cyan, Self> {
        self.cyan()
    }

    fn success(&self) -> FgColorDisplay<'_, colors::Green, Self> {
        self.green()
    }
}

impl<D> TextColors for D {}

/// If the OTT has an expiration this will return the remaining time as a pretty printed string\
/// If 30 seconds are left this will yield "30s"\
/// If 30 minutes are left this will yield "30m"
pub fn pretty_expiration(ott: &IdentityEnrollmentsOtt) -> Option<String> {
    ott.expires_at
        .as_ref()
        .and_then(|exp| exp.parse::<DateTime<Utc>>().ok())
        .map(|exp| exp - Utc::now())
        .map(|duration| {
            let seconds = duration.num_seconds();
            let minutes = seconds / 60;

            if minutes > 0 {
                format!("{}m", minutes)
            } else {
                format!("{}s", seconds)
            }
        })
}
