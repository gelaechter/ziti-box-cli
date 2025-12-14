use crate::config::Serializable;
use chrono::{DateTime, Utc};
use color_eyre::{
    Result,
    eyre::{Context, eyre},
    owo_colors::OwoColorize,
};
use comfy_table::Table;
use dialoguer::{Confirm, Input, Password};
use keyring::KeyringEntry;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{error::Error, path::PathBuf};
use ziti_api::{
    apis::{
        authentication_api::authenticate,
        configuration::{ApiKey, Configuration},
        identity_api::{detail_identity, list_identities},
        informational_api,
    },
    models::{
        Authenticate, IdentityDetail, IdentityEnrollments,
        identity_detail::EdgeRouterConnectionStatus,
    },
};

static CONFIG_PATH: Lazy<PathBuf> =
    Lazy::new(|| dirs_next::config_dir().unwrap().join("zitibox/api.json"));

const ZITIBOX_ROLE: &str = "ZitiBox";

#[derive(Serialize, Deserialize)]
pub struct ZitiApi {
    /// If our reqwest client should also accept
    accept_bad_tls: bool,
    /// The authenticating user
    username: String,
    /// ISO 8061 datetime denoting the session expiration
    session_expiration: String,
    /// OpenApi configuration
    conf: Configuration,
}

impl ZitiApi {
    /// Constructs a ZitiApi by first trying to find the config and otherwise starting first time setup
    pub async fn load() -> Result<Option<Self>> {
        match ZitiApi::load_from_file(&CONFIG_PATH).await {
            Ok(opt) => Ok(match opt {
                // Either use the existing config
                Some(mut api) => {
                    // Additionally build reqwest client based on `accept_bad_tls`, since we can't serialize it
                    api.conf.client = Client::builder()
                        .danger_accept_invalid_certs(api.accept_bad_tls)
                        .build()?;

                    // Ziti sessions last about half an hour, reauth if it expires
                    if api.session_expired()? {
                        api.reauth().await?
                    }

                    Some(api)
                }
                // Or create start first time configuration
                None => None,
            }),
            Err(e) => Err(e).wrap_err("Couldn't load configuration file"),
        }
    }

    /// Checks if the session has expired
    fn session_expired(&self) -> Result<bool> {
        Ok(self.session_expiration.parse::<DateTime<Utc>>()? < Utc::now())
    }

    /// Lets us reauth using existing credentials if our sessione expires
    async fn reauth(&mut self) -> Result<()> {
        let username = self.username.clone();
        let entry = KeyringEntry::try_new(&username)?;
        let password = entry.get_secret().await?;

        let mut auth = Authenticate::new();
        auth.username = Some(username);
        auth.password = Some(password);

        let session = authenticate(&self.conf, "password", Some(auth)).await?;

        println!(
            "{} {}",
            "Successfully reauthenticated as".cyan(),
            session
                .data
                .identity
                .name
                .unwrap_or(self.username.clone())
                .cyan()
        );

        self.conf.api_key = Some(ApiKey {
            prefix: None,
            key: session.data.token,
        });

        Ok(())
    }

    /// Starts the first time configuration dialogue
    pub async fn first_time_configuration() -> Result<Self> {
        let mut conf = Configuration::new();

        // We may need to allow self signed certs
        let url: String = Input::new()
            .with_prompt("Enter controller url (e.g. https://controller.ziti:1280)")
            .with_initial_text("https://")
            .interact_text()?;

        let url = format!("{url}/edge/management/v1");

        conf.base_path = url;
        conf.client = reqwest::Client::new();

        let mut accept_bad_tls = false;

        // Retry if we allow bad tls
        loop {
            // Check if we can connect
            match informational_api::list_root(&conf).await {
                // Exit retry loop if the connection works
                Ok(_) => {
                    println!("{}", "Endpoint is responding".green());
                    break;
                }
                Err(e) => {
                    // Check if this might be because of self signed certs
                    if let ziti_api::apis::Error::Reqwest(ref err) = e
                        // here we need to access the underlying SSL error
                        && let Some(err) = err.source().and_then(|err| err.source())
                        && format!("{}", err)
                            .contains("self-signed certificate in certificate chain")
                    {
                        println!("{}", "Cannot connect to endpoint, the controller certificate seems to be self-signed.".bright_red());

                        // Ask user to allow bad tls
                        accept_bad_tls = Confirm::new()
                            .with_prompt(format!(
                                "{}",
                                "Accept invalid TLS certs? Only allow this if you self signed your certs.".bright_red()
                            ))
                            .interact()?;

                        // If so change reqwest settings and retry
                        conf.client = reqwest::Client::builder()
                            .danger_accept_invalid_certs(accept_bad_tls)
                            .build()?;

                        println!("Retrying...")
                    } else {
                        // If this is a generic error then just error out
                        println!(
                        "{}",
                        "Cannot connect to endpoint, please make sure you entered the correct URL."
                            .red()
                    );
                        return Err(e).wrap_err("Couldn't contact endpoint");
                    }
                }
            };
        }

        let mut auth = Authenticate::new();

        loop {
            let mut username_prompt = Input::new().with_prompt("Enter username");
            if let Some(username) = auth.username {
                username_prompt = username_prompt.with_initial_text(username);
            }
            let username: String = username_prompt.interact_text()?;
            let password = Password::new().with_prompt("Enter password").interact()?;

            auth.username = Some(username.clone());
            auth.password = Some(password.clone());

            // Check if we can authenticate
            match authenticate(&conf, "password", Some(auth.clone())).await {
                Ok(session) => {
                    // If successful
                    let msg = format!(
                        "Successfully authenticated as {}. Saving config...",
                        session.data.identity.name.unwrap_or(username.clone())
                    );
                    println!("{}", msg.green());

                    // save the user password into a local keyring
                    let entry = KeyringEntry::try_new(&username)?;
                    entry.set_secret(password).await?;

                    // save the api token
                    conf.api_key = Some(ApiKey {
                        prefix: None,
                        key: session.data.token,
                    });

                    // save the username, OpenApi config and session expiration date
                    let api = ZitiApi {
                        accept_bad_tls,
                        conf,
                        username,
                        session_expiration: session.data.expires_at,
                    };

                    api.save_to_file(&CONFIG_PATH)
                        .await
                        .wrap_err("Couldn't save config")?;

                    return Ok(api);
                }
                Err(_) => {
                    println!(
                        "{}",
                        "Couldn't authenticate. Make sure you entered the correct credentials:"
                            .bright_red()
                    )
                }
            };
        }
    }

    /// Lists all ziti box identites
    pub async fn list_ziti_boxes(&self) -> Result<()> {
        let identities: Vec<IdentityDetail> =
            list_identities(&self.conf, None, None, None, None, None)
                .await
                .wrap_err("Couldn't request ZitiBox identities")?
                .data
                .into_iter()
                // Filter zitiboxes by role
                .filter(|id| {
                    id.role_attributes
                        .as_ref()
                        .is_some_and(|roles| roles.contains(&ZITIBOX_ROLE.to_string()))
                })
                .collect();

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
                match Self::parse_enrollment_state(&zitibox.enrollment) {
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

    /// Takes a ziti_api::IdentityEnrollments and parses it into our own EnrollmentState
    /// this gives us an ergonomic type for UI
    pub fn parse_enrollment_state(enrollment: &IdentityEnrollments) -> EnrollmentState {
        match enrollment {
            IdentityEnrollments { ott: None, .. } => EnrollmentState::Enrolled,
            IdentityEnrollments { ott: Some(ott), .. } => {
                if let Some(date) = &ott.expires_at {
                    if let Ok(ott_expiration) = date.parse::<DateTime<Utc>>()
                        && ott_expiration < Utc::now()
                    {
                        EnrollmentState::Expired
                    } else {
                        EnrollmentState::ReadyToEnroll
                    }
                } else {
                    EnrollmentState::Unknown
                }
            }
        }
    }

    pub async fn get_ziti_box(&self, id: String) -> Result<IdentityDetail> {
        let identity = detail_identity(&self.conf, &id).await?.data;
        if let Some(roles) = &identity.role_attributes
            && roles.contains(&ZITIBOX_ROLE.to_string())
        {
            Ok(*identity)
        } else {
            Err(eyre!(
                "This identity doesn't seem to be a ZitiBox identity. The \"ZitiBox\" role is missing."
            ))
        }
    }
}

pub enum EnrollmentState {
    Enrolled,
    Expired,
    ReadyToEnroll,
    Unknown,
}
