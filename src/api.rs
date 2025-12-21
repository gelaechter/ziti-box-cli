use crate::{TextColors, config::Serializable};
use chrono::{DateTime, Duration, Utc};
use color_eyre::{
    Result,
    eyre::{Context, eyre},
};
use keyring::KeyringEntry;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::{error::Error, path::PathBuf, sync::LazyLock};
use ziti_api::{
    apis::{
        authentication_api::authenticate,
        configuration::{ApiKey, Configuration},
        identity_api::{create_identity, delete_identity, detail_identity, list_identities},
        informational_api::{self},
    },
    models::{
        Authenticate, CurrentApiSessionDetail, EnrollmentCreate, IdentityCreate,
        IdentityCreateEnrollment, IdentityDetail, IdentityEnrollments, IdentityType,
        enrollment_create::Method,
    },
};

pub static CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| dirs_next::config_dir().unwrap().join("zitibox/api.json"));

const ZITIBOX_ROLE: &str = "ZitiBox";

/// API providing us access to the OpenZiti Controller
/// An instance of this API implies the following:
///     - The url the correct base path for the edge management api
///     - The username is valid
///     - A valid session has at some point existed and the user password is stored in the keyring
#[derive(Serialize, Deserialize)]
pub struct ZitiApi {
    /// Ziti endpoint url
    url: Url,
    /// If our reqwest client should also accept
    accept_bad_tls: bool,
    /// The authenticating user
    username: String,
    /// ISO 8061 datetime denoting the session expiration
    session_expiration: String,
    /// OpenApi configuration
    #[serde(skip)]
    // no serialization because it is partly unserializable and contains credentials
    conf: Configuration,
}

impl ZitiApi {
    /// Saves this configuration of the ZitiApi
    pub async fn save(
        url: Url,
        accept_bad_tls: bool,
        username: String,
        password: String,
    ) -> Result<ZitiApi> {
        let mut conf = Configuration::new();
        conf.base_path = url.to_string();
        conf.client = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_bad_tls)
            .build()?;

        let mut auth = Authenticate::new();
        auth.username = Some(username.clone());
        auth.password = Some(password.clone());

        match authenticate(&conf, "password", Some(auth)).await {
            Ok(session) => {
                //  Save credentials to keyring
                let entry = KeyringEntry::try_new(&username)?;
                entry.set_secret(password).await?;

                let entry = KeyringEntry::try_new("session")?;
                entry.set_secret(session.data.token.clone()).await?;

                // Write token to config
                conf.api_key = Some(ApiKey {
                    prefix: None,
                    key: session.data.token,
                });

                let api = ZitiApi {
                    url,
                    accept_bad_tls,
                    username,
                    session_expiration: session.data.expires_at,
                    conf,
                };

                api.save_to_file(&CONFIG_PATH)
                    .await
                    .wrap_err("Couldn't save config")?;

                Ok(api)
            }
            Err(e) => Err(eyre!(e)),
        }
    }

    /// Trys to load the ZitiApi from a saved config
    pub async fn load() -> Result<Option<Self>> {
        match ZitiApi::load_from_file(&CONFIG_PATH).await {
            Ok(opt) => Ok(match opt {
                // Either use the existing config
                Some(mut api) => {
                    // Instantiate reqwest client
                    api.conf.client = Client::builder()
                        .danger_accept_invalid_certs(api.accept_bad_tls)
                        .build()?;

                    // Set url
                    api.conf.base_path = api.url.to_string();

                    // Ziti sessions last about half an hour, reauth if it has expired since then
                    let (token, reauth) = if api.session_expired()? {
                        // Reauth if expired
                        let session = api.reauth().await?;
                        api.session_expiration = session.expires_at;

                        let msg =
                            format!("Successfully reauthenticated as {}", api.username.clone())
                                .info()
                                .to_string();
                        println!("{}", msg);

                        // Save session token and return it
                        let entry = KeyringEntry::try_new("session")?;
                        entry.set_secret(session.token.clone()).await?;
                        (session.token, true)
                    } else {
                        // Load session token if still valid and reutrn it
                        let entry = KeyringEntry::try_new("session")?;
                        (entry.get_secret().await?, false)
                    };

                    // Set token
                    api.conf.api_key = Some(ApiKey {
                        prefix: None,
                        key: token,
                    });

                    // And save the new expiration datetime if we had to reauth
                    if reauth {
                        api.save_to_file(&CONFIG_PATH)
                            .await
                            .wrap_err("Couldn't save config")?;
                    }

                    Some(api)
                }
                None => None,
            }),
            Err(e) => Err(e).wrap_err("Couldn't load configuration file"),
        }
    }

    /// Checks if an endpoint is reachable
    pub async fn try_endpoint(
        url: Url,
        accept_bad_tls: bool,
    ) -> Result<(), EndpointError<Box<dyn Error>>> {
        let mut conf = Configuration::new();
        conf.base_path = url.to_string();
        conf.client = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_bad_tls)
            .build()
            .map_err(|e| EndpointError::Unknown(e.into()))?;

        match informational_api::list_root(&conf).await {
            // Exit retry loop if the connection works
            Ok(_) => Ok(()),
            Err(e) => {
                // Check if this might be because of self signed certs
                if let ziti_api::apis::Error::Reqwest(ref err) = e
                        // here we need to access the underlying SSL error
                        && let Some(err) = err.source().and_then(|err| err.source())
                        && format!("{}", err)
                            .contains("self-signed certificate in certificate chain")
                {
                    Err(EndpointError::TLSError)
                } else {
                    Err(EndpointError::Unknown(e.into()))
                }
            }
        }
    }

    /// Returns true if authentication was successful, otherwise returns an
    pub async fn try_authenticate(
        url: Url,
        accept_bad_tls: bool,
        username: String,
        password: String,
    ) -> Result<bool> {
        let mut conf = Configuration::new();
        conf.base_path = url.to_string();
        conf.client = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_bad_tls)
            .build()?;

        let mut auth = Authenticate::new();
        auth.username = Some(username.clone());
        auth.password = Some(password.clone());

        match authenticate(&conf, "password", Some(auth)).await {
            // Successfully authenticated
            Ok(_) => Ok(true),
            // Wrong credentials
            Err(ziti_api::apis::Error::ResponseError(response_content)) => {
                Ok(response_content.status == StatusCode::UNAUTHORIZED)
            }
            // Unknown error
            Err(e) => Err(eyre!(e)),
        }
    }

    /// Checks if the session has expired
    fn session_expired(&self) -> Result<bool> {
        Ok(self.session_expiration.parse::<DateTime<Utc>>()? < Utc::now())
    }

    /// Lets us reauth using existing credentials if our sessione expires
    async fn reauth(&mut self) -> Result<CurrentApiSessionDetail> {
        let username = self.username.clone();
        let entry = KeyringEntry::try_new(&username)?;
        let password = entry.get_secret().await?;

        let mut auth = Authenticate::new();
        auth.username = Some(username);
        auth.password = Some(password);

        let session = authenticate(&self.conf, "password", Some(auth)).await?;

        self.conf.api_key = Some(ApiKey {
            prefix: None,
            key: session.data.token.clone(),
        });

        Ok(*session.data)
    }

    /// Lists all ziti box identites
    pub async fn list_ziti_boxes(&self) -> Result<Vec<IdentityDetail>> {
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

        Ok(identities)
    }

    /// Resets the enrollment for an identity with a string
    pub async fn reset_enrollment(&self, id: String) -> Result<()> {
        // This ensures that the id belongs to a ZitiBox
        let zitibox = self.get_ziti_box(id).await?;

        // Delete the previous enrollment (if it exists)
        if let Some(ott) = &zitibox.enrollment.ott
            && let Some(id) = &ott.id
        {
            ziti_api::apis::enrollment_api::delete_enrollment(&self.conf, id)
                .await
                .wrap_err("Couldn't delete the enrollment for this identity")?;
        };

        // Create a new one
        ziti_api::apis::enrollment_api::create_enrollment(
            &self.conf,
            EnrollmentCreate {
                expires_at: (Utc::now() + Duration::minutes(30)).to_rfc3339(),
                identity_id: zitibox.id,
                method: Method::Ott,
                ..Default::default()
            },
        )
        .await?;

        Ok(())
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

    pub async fn create_ziti_box(&self, name: String) -> Result<()> {
        create_identity(
            &self.conf,
            IdentityCreate {
                enrollment: Some(Box::new(IdentityCreateEnrollment {
                    ott: Some(true),
                    ..Default::default()
                })),
                name,
                role_attributes: Some(Some(vec![ZITIBOX_ROLE.to_string()])),
                r#type: IdentityType::Default,
                ..Default::default()
            },
        )
        .await
        .wrap_err("Couldn't create Ziti Box identity")?;

        Ok(())
    }

    pub async fn delete_ziti_box(&self, ziti_box_id: String) -> Result<()> {
        delete_identity(&self.conf, &ziti_box_id)
            .await
            .wrap_err("Couldn't delete Ziti Box identity")?;

        Ok(())
    }

    pub async fn bootstrap_ziti_network(&self) -> Result<()> {
        // Heres the plan
        // 1. Check if a ZitiBoxCli identity already exists
        // 2. If it doesn't, create it
        // 3. If need be, re-enroll it
        // 4. Enroll the created OTT using Edge Client API
        // 5. Download the newly enrolled certificate
        // 6. Use the identity file with the ZitiAPI rust crate
        // 7. Access the ZitiBox using russh
        todo!()
    }
}

#[derive(Debug)]
pub enum EndpointError<T> {
    TLSError,
    Unknown(T),
}

#[derive(PartialEq, Eq)]
pub enum EnrollmentState {
    Enrolled,
    Expired,
    ReadyToEnroll,
    Unknown,
}

impl From<&IdentityEnrollments> for EnrollmentState {
    /// Takes a ziti_api::IdentityEnrollments and parses it into our own EnrollmentState\
    /// EnrollmentState is a lot more ergonomic for UI code
    fn from(enrollment: &IdentityEnrollments) -> Self {
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
}