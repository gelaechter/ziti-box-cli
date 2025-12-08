pub mod api;
mod config;
mod image;

use clap::{Parser, crate_version};
use color_eyre::{Result, eyre::Context};
use once_cell::sync::Lazy;
use ziti_api::models::IdentityEnrollmentsOtt;

use crate::{api::ZitiApi, image::{choose_image, create_zitibox_image}};

// Define flags
#[derive(Parser, Debug)]
#[command(name = "Ziti Box utility cli")]
#[command(version = crate_version!())]
#[command(about = "Lets you manage your Ziti-Boxes", long_about = None)]
struct Args {
    /// First time configuration
    #[arg(long, default_value_t = false)]
    configure: bool,

    /// List ziti boxes
    #[arg(long, default_value_t = false)]
    list: bool,

    /// Produce an image for a Ziti Box
    #[arg(long, default_value_t = false)]
    image: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.configure {
        ZitiApi::first_time_configuration().await?;
        return Ok(());
    }

    if args.list {
        ZitiApi::new()
            .await?
            .list_ziti_boxes()
            .await
            .wrap_err("Couldn't list ziti boxes...")?;
        return Ok(());
    }

    if args.image {
        let image = create_zitibox_image(
            IdentityEnrollmentsOtt::new()
        )?;

        return Ok(());
    }

    Ok(())
}
