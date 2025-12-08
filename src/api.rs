use std::path::PathBuf;

use asky::{Confirm, Password, Text};
use chrono::{DateTime, Utc};
use color_eyre::{Result, eyre::Context};
use comfy_table::Table;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use ziti_api::{
    apis::{
        authentication_api::authenticate,
        configuration::{ApiKey, Configuration},
        identity_api::list_identities,
        informational_api,
    },
    models::{Authenticate, IdentityEnrollments, identity_detail::EdgeRouterConnectionStatus},
};

use crate::config::Serializable;

static CONFIG_PATH: Lazy<PathBuf> =
    Lazy::new(|| dirs_next::config_dir().unwrap().join("zitibox/api.json"));

#[derive(Serialize, Deserialize)]
pub struct ZitiApi {
    /// If our reqwest client should also accept
    accept_bad_tls: bool,
    /// OpenApi configuration
    conf: Configuration,
}

impl ZitiApi {
    /// Constructs a ZitiApi by first trying to find the config and otherwise starting first time setup
    pub async fn new() -> Result<Self> {
        match ZitiApi::load_from_file(&CONFIG_PATH).await {
            Ok(opt) => Ok(match opt {
                // Either use the existing config
                Some(mut api) => {
                    // Additionally build reqwest client based on `accept_bad_tls`, since we can't serialize it
                    api.conf.client = Client::builder()
                        .danger_accept_invalid_certs(api.accept_bad_tls)
                        .build()?;

                    api
                }
                // Or create start first time configuration
                None => {
                    println!("Couldn't find a configuration, starting first time configuration...");
                    ZitiApi::first_time_configuration().await?
                }
            }),
            Err(e) => Err(e).wrap_err("Couldn't load configuration file"),
        }
    }

    /// Starts the first time configuration dialogue
    pub async fn first_time_configuration() -> Result<Self> {
        let mut conf = Configuration::new();

        // We may need to allow self signed certs
        let accept_bad_tls = Confirm::new(
            "Accept invalid TLS certs? Only allow this if you self signed your certs.",
        )
        .prompt()?;
        let host =
            Text::new("Enter controller URL (e.g. https://controller.ziti:1280)").prompt()?;

        conf.base_path = host;
        conf.client = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_bad_tls)
            .build()?;

        // Check if we can connect
        match informational_api::list_root(&conf).await {
            Ok(_) => {
                println!("Endpoint is working");
            }
            Err(e) => {
                println!("Cannot contact endpoint, please make sure you entered the correct URL.");
                return Err(e).wrap_err("Couldn't contact endpoint");
            }
        };

        let username = Text::new("Enter username").prompt()?;
        let password = Password::new("Enter password").prompt()?;

        let mut auth = Authenticate::new();
        auth.username = Some(username);
        auth.password = Some(password);

        // Check if we can authenticate
        let api = match authenticate(&conf, "password", Some(auth)).await {
            Ok(session) => {
                println!("Authentication successful! Saving config...");
                conf.api_key = Some(ApiKey {
                    prefix: None,
                    key: session.data.token,
                });

                Ok(ZitiApi {
                    accept_bad_tls,
                    conf,
                })
            }
            Err(e) => Err(e).wrap_err("Couldn't authenticate"),
        }?;

        api.save_to_file(&CONFIG_PATH)
            .await
            .wrap_err("Couldn't save config")?;

        Ok(api)
    }

    /// Lists all ziti box identites
    pub async fn list_ziti_boxes(&self) -> Result<()> {
        let identities = list_identities(&self.conf, None, None, None, None, None)
            .await
            .wrap_err("Couldn't request ZitiBox identities")?
            .data;

        let mut table = Table::new();
        table.set_header(vec!["Status", "Name", "Enrollment"]);

        for zitibox in identities {
            table.add_row(vec![
                match &zitibox.edge_router_connection_status {
                    EdgeRouterConnectionStatus::Online => "Online",
                    EdgeRouterConnectionStatus::Offline => "Offline",
                    EdgeRouterConnectionStatus::Unknown => "Unknown",
                },
                &zitibox.name,
                match &*zitibox.enrollment {
                    IdentityEnrollments { ott: None, .. } => "Already enrolled",
                    IdentityEnrollments { ott: Some(ott), .. } => {
                        if let Some(date) = &ott.expires_at {
                            if date
                                .parse::<DateTime<Utc>>()
                                .wrap_err("Cannot parse OTT expiration date")?
                                < Utc::now()
                            {
                                "Enrollment expired"
                            } else {
                                "Ready to enroll"
                            }
                        } else {
                            "Unknown enrollment state"
                        }
                    }
                },
            ]);
        }

        println!("{table}");

        Ok(())
    }
}
