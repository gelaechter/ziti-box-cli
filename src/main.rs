mod api;
mod config;
mod image;

use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{Context, eyre},
    owo_colors::OwoColorize,
};
use comfy_table::Table;
use dialoguer::{Confirm, Input, Password};
use keyring::set_global_service_name;
use reqwest::Url;
use ziti_api::models::identity_detail::EdgeRouterConnectionStatus;

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
    /// Produce an Ziti Box image for a Ziti Box identity
    Image {
        #[arg()]
        id: String,
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
        SubCommands::Image { id } => cmd_create_img(id).await,
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
        println!("{}", "There are no Ziti Box identities to display.".cyan());
        return Ok(());
    }

    println!("{}", "Listing Ziti Box identities:".cyan());

    // Build a table from our identities
    let mut table = Table::new();
    table.set_header(vec!["Id", "Status", "Name", "Enrollment"]);

    for zitibox in identities {
        table.add_row(vec![
            zitibox.id,
            match &zitibox.edge_router_connection_status {
                EdgeRouterConnectionStatus::Online => "Online".green().to_string(),
                EdgeRouterConnectionStatus::Offline => "Offline".red().to_string(),
                EdgeRouterConnectionStatus::Unknown => "Unknown".yellow().to_string(),
            },
            zitibox.name,
            match ZitiApi::parse_enrollment_state(&zitibox.enrollment) {
                EnrollmentState::Enrolled => "Already enrolled".green().to_string(),
                EnrollmentState::Expired => "Enrollment expired".red().to_string(),
                EnrollmentState::ReadyToEnroll => "Ready to enroll".blue().to_string(),
                EnrollmentState::Unknown => "Unknown enrollment state".yellow().to_string(),
            },
        ]);
    }

    println!("{table}");
    Ok(())
}

/// Creates a disk image for a Ziti Box identity
async fn cmd_create_img(zitibox_id: String) -> Result<()> {
    let ziti_box = construct_ziti_api().await?.get_ziti_box(zitibox_id).await?;
    // Check if the ZitiBox is ready to be enrolled
    if !matches!(
        ZitiApi::parse_enrollment_state(&ziti_box.enrollment),
        EnrollmentState::ReadyToEnroll
    ) {
        return Err(eyre!("This ZitiBox is not ready to be enrolled"));
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
                println!("{}", "Endpoint is responding".green());
                break;
            }
            Err(api::EndpointError::TLSError) => {
                println!("{}", "Cannot connect to endpoint, the controller certificate seems to be self-signed.".bright_red());

                // Ask user to allow bad tls
                accept_bad_tls = Confirm::new()
                    .with_prompt(format!(
                        "{}",
                        "Accept invalid TLS certs? Only allow this if you self signed your certs."
                            .bright_red()
                    ))
                    .interact()?;

                // If so change reqwest settings and retry
            }
            // If this is a generic error then just error out
            Err(api::EndpointError::Unknown(e)) => {
                println!(
                    "{}",
                    "Cannot connect to endpoint, please make sure you entered the correct URL."
                        .red()
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
                    println!("{}", "The provided credentials are incorrect. Ensure you entered the correct credentials.".bright_red())
                }
            }
            Err(e) => {
                return Err(e).wrap_err("Error during authentication");
            }
        };
    }
}
