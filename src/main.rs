pub mod api;
mod config;
mod image;

use clap::{Parser, Subcommand};
use color_eyre::{
    Result,
    eyre::{Context, eyre}, owo_colors::OwoColorize,
};
use keyring::set_global_service_name;

use crate::{
    api::{EnrollmentState, ZitiApi},
    image::create_zitibox_image,
};

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

    let args = Args::parse();
    match args.subcommand {
        SubCommands::Configure => {
            ZitiApi::first_time_configuration().await?;
            return Ok(());
        }
        SubCommands::List => {
            let ziti_api = ziti_api()
                .await?
                .list_ziti_boxes()
                .await
                .wrap_err("Couldn't list ziti boxes...")?;
            return Ok(());
        }
        SubCommands::Image { id } => {
            let ziti_box = ziti_api().await?.get_ziti_box(id).await?;
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
                create_zitibox_image(jwt)
            } else {
                Err(eyre!("Ziti Box identity enrollment didn't contain a JWT"))
            }
        }
    }
}

// Either loads the existing ZitiApi or starts first time configuration
async fn ziti_api() -> Result<ZitiApi> {
    if let Some(api) = ZitiApi::load().await? {
        Ok(api)
    } else {
        println!(
            "{}",
            "Couldn't find a configuration, starting first time configuration...".cyan()
        );
        ZitiApi::first_time_configuration().await
    }
}
