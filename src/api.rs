//! This module contains helpers for the Ziti REST API.

use crate::{
    config::Serializable,
    secrets::{self, KeyStoreError, SecretManager},
};
use chrono::{DateTime, Duration, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{error::Error as StdError, fmt::Debug, path::PathBuf, sync::LazyLock};
use ziti_api::{
    apis::{
        self, Error as ApiError, ResponseContent,
        authentication_api::{AuthenticateError, authenticate},
        config_api::{create_config, list_config_types},
        configuration::{ApiKey, Configuration},
        current_api_session_api::{GetCurrentApiSessionError, get_current_api_session},
        enrollment_api::{create_enrollment, delete_enrollment},
        identity_api::{
            create_identity, delete_identity, detail_identity, list_identities,
            list_identity_services,
        },
        informational_api::{self},
        service_api::create_service,
        service_policy_api::create_service_policy,
    },
    models::{
        Authenticate, ConfigCreate, DialBind, EnrollmentCreate, IdentityCreate,
        IdentityCreateEnrollment, IdentityDetail, IdentityEnrollments, IdentityType, Semantic,
        ServiceCreate, ServiceDetail, ServicePolicyCreate, enrollment_create::Method,
    },
};

pub static CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| dirs_next::config_dir().unwrap().join("zitibox/api.config"));

const ZITIBOX_ROLE: &str = "ZitiBox";

/// specifically for Edge Management API Errors
type BoxedAny = Box<dyn Debug + Send + Sync + 'static>;
type BoxedError = Box<dyn StdError + Send + Sync + 'static>;

#[derive(thiserror::Error, Debug)]
pub enum ZitiApiError {
    #[error("The configuration does not contain a token")]
    NoToken,
    #[error("The provided credentials were incorrect")]
    IncorrectCredentials,
    #[error("The API response was malformed: `{0}`")]
    MalformedResponse(String),
    #[error("The identity with id `{0}` is not a Ziti Box; The \"ZitiBox\" role is missing")]
    NotAZitiBox(String),
    #[error("The endpoint does not have a valid TLS certificate")]
    SelfSignedTLS,
    #[error("Error accessing the KeyStore")]
    KeyStore(KeyStoreError),
    #[error("Error during request to Ziti Edge Management API")]
    EdgeManagementApi(BoxedAny),
    #[error(transparent)]
    Other(#[from] BoxedError),
}

impl From<KeyStoreError> for ZitiApiError {
    fn from(err: KeyStoreError) -> Self {
        Self::KeyStore(err)
    }
}

impl<T> From<ApiError<T>> for ZitiApiError
where
    T: Debug + Send + Sync + 'static,
{
    fn from(err: ApiError<T>) -> Self {
        Self::EdgeManagementApi(Box::new(err))
    }
}

/// Represents the configuration for a Ziti API
#[derive(Debug, Serialize, Deserialize)]
pub struct ZitiConfig {
    /// Ziti endpoint url
    pub url: Url,
    /// If our reqwest client should also accept
    pub accept_bad_tls: bool,
    /// The authenticating user
    pub username: String,
}

impl ZitiConfig {
    /// Saves the config to disk
    pub async fn save(&self) -> Result<(), ZitiApiError> {
        self.save_to_file(&CONFIG_PATH)
            .await
            .map_err(ZitiApiError::Other)
    }

    /// Loads the config from disk
    pub async fn load() -> Result<Option<Self>, ZitiApiError> {
        Self::load_from_file(&CONFIG_PATH).await.map_err(Into::into)
    }
}

/// API providing us access to the OpenZiti Controller
///
/// An instance of this implies that the contained Configuration
/// is ready to make requests to the Edge Management API
pub struct ZitiApi {
    conf: Configuration,
}

impl ZitiApi {
    /// Returns Some if a valid session still exists, None if the last session is invalid
    pub async fn try_from_session(ziti_conf: &ZitiConfig) -> Result<Option<Self>, ZitiApiError> {
        let token = match secrets::key_store().get_secret("session").await {
            Ok(t) => t,
            Err(KeyStoreError::NoEntry) => return Ok(None), // Return early if there is no entry
            Err(e) => return Err(e.into()),                 // Propagate the error for anything else
        };

        let base_path = ziti_conf.url.to_string();

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(ziti_conf.accept_bad_tls)
            .build()
            .map_err(|e| ZitiApiError::Other(Box::new(e)))?;

        let api_key = Some(ApiKey {
            prefix: None,
            key: token,
        });

        let conf = Configuration {
            base_path,
            client,
            api_key,
            ..Default::default()
        };

        let session = get_current_api_session(&conf).await;
        match session {
            Ok(_) => Ok(Some(Self { conf })),
            // If we get a 401 UNAUTHORIZED we know that the token is expired, so return None
            Err(apis::Error::ResponseError(ResponseContent {
                entity: Some(GetCurrentApiSessionError::Status401(_)),
                ..
            })) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Authenticate and return a session
    /// Tries to authenticate using the given ZitiConfig and the password
    /// If successful then stores the password and session for reauth
    /// Returns [`ZitiApiError::IncorrectCredentials`] if the credentials are incorrect
    pub async fn authenticate(
        ziti_conf: &ZitiConfig,
        password: String,
    ) -> Result<Self, ZitiApiError> {
        let base_path = ziti_conf.url.to_string();

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(ziti_conf.accept_bad_tls)
            .build()
            .map_err(|e| ZitiApiError::Other(Box::new(e)))?;

        let mut conf = Configuration {
            base_path,
            client,
            ..Default::default()
        };

        let auth = Authenticate {
            username: Some(ziti_conf.username.clone()),
            password: Some(password),
            ..Default::default()
        };

        let token = match authenticate(&conf, "password", Some(auth)).await {
            Ok(s) => s.data.token,
            Err(ApiError::ResponseError(ResponseContent {
                entity: Some(AuthenticateError::Status401(_)),
                ..
            })) => return Err(ZitiApiError::IncorrectCredentials),
            Err(e) => return Err(e.into()),
        };

        conf.api_key = Some(ApiKey {
            prefix: None,
            key: token,
        });

        Ok(Self { conf })
    }

    /// Stores a valid ZitiApi and its token using the [`secrets::KeyStore`]
    pub async fn store_session_token(&self) -> Result<(), ZitiApiError> {
        let token = match &self.conf.api_key {
            None => return Err(ZitiApiError::NoToken),
            Some(ApiKey { key, .. }) => key,
        };

        secrets::key_store().set_secret("session", token).await?;

        Ok(())
    }

    /// Checks if an endpoint is reachable
    pub async fn try_endpoint(url: Url, accept_bad_tls: bool) -> Result<(), ZitiApiError> {
        let mut conf = Configuration::new();
        conf.base_path = url.to_string();

        conf.client = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_bad_tls)
            .build()
            .map_err(|e| ZitiApiError::Other(Box::new(e)))?;

        // TODO: Check remote API version against local API version
        let _version = match informational_api::list_root(&conf).await {
            Ok(envelope) => Ok(*envelope.data),
            Err(e) => {
                // Check if this might be caused by self signed certs
                if let ApiError::Reqwest(ref err) = e
                        // here we need to access the underlying SSL error
                        && let Some(err) = err.source().and_then(|err| err.source())
                        && format!("{err}")
                            .contains("self-signed certificate in certificate chain")
                {
                    Err(ZitiApiError::SelfSignedTLS)
                } else {
                    Err(e.into())
                }
            }
        }?;

        Ok(())
    }

    /// Lists all identities
    pub async fn list_identities(&self) -> Result<Vec<IdentityDetail>, ZitiApiError> {
        let identities = list_identities(&self.conf, None, None, None, None, None)
            .await?
            .data;

        Ok(identities)
    }

    /// Lists all ziti box identites
    pub async fn list_ziti_boxes(&self) -> Result<Vec<IdentityDetail>, ZitiApiError> {
        let identities: Vec<IdentityDetail> = self
            .list_identities()
            .await?
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

    pub async fn list_edge_routers(&self) -> Result<Vec<IdentityDetail>, ZitiApiError> {
        let edge_routers = self
            .list_identities()
            .await?
            .into_iter()
            // FIXME: As far as I understand this isn't explicitly an edge router but can also be a transit router.
            .filter(|id| id.type_id == "Router")
            .collect();
        Ok(edge_routers)
    }

    /// Resets the enrollment for an identity with a string
    pub async fn reset_enrollment(&self, id: String) -> Result<(), ZitiApiError> {
        // This ensures that the id belongs to a ZitiBox
        let zitibox = self.get_ziti_box(id).await?;

        // Delete the previous enrollment (if it exists)
        if let Some(ott) = &zitibox.enrollment.ott
            && let Some(id) = &ott.id
        {
            delete_enrollment(&self.conf, id).await?;
        }

        // Create a new enrollment
        create_enrollment(
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

    /// Gets a ziti box by id. The existence of the "ZitiBox" role is ensured.
    pub async fn get_ziti_box(&self, id: String) -> Result<IdentityDetail, ZitiApiError> {
        let identity = detail_identity(&self.conf, &id).await?.data;
        // If our identity has the ZitiBox role it is a ZitiBox
        if let Some(roles) = &identity.role_attributes
            && roles.contains(&ZITIBOX_ROLE.to_string())
        {
            Ok(*identity)
        } else {
            // If not error out
            Err(ZitiApiError::NotAZitiBox(id))
        }
    }

    /// Lists services belonging to an identity
    pub async fn list_identity_services(
        &self,
        id: &str,
    ) -> Result<Vec<ServiceDetail>, ZitiApiError> {
        unimplemented!("https://github.com/openziti/ziti/issues/3481");
        let services = list_identity_services(&self.conf, id, None, Some("dial")).await?;

        Ok(services.data)
    }

    /// This creates a ziti box with a
    pub async fn create_ziti_box(&self, name: String) -> Result<(), ZitiApiError> {
        create_identity(
            &self.conf,
            IdentityCreate {
                enrollment: Some(Box::new(IdentityCreateEnrollment {
                    // Create with an OTT
                    ott: Some(true),
                    ..Default::default()
                })),
                name,
                // Add the Ziti Box role
                role_attributes: Some(Some(vec![ZITIBOX_ROLE.to_string()])),
                // explicit because IdentityType::default() yields IdentityType::User
                r#type: IdentityType::Default,
                ..Default::default()
            },
        )
        .await?;

        Ok(())
    }

    pub async fn delete_ziti_box(&self, ziti_box_id: String) -> Result<(), ZitiApiError> {
        delete_identity(&self.conf, &ziti_box_id).await?;

        Ok(())
    }

    /// Adds an Open Ziti Service that routes the address and its ports through an edge-router \
    /// thus allowing communication with the internet
    ///
    /// The do this we need to create:
    /// 1. a host.v1 config that defines what the host (edge-router) will be allowed to passthrough
    /// 2. a intercept.v1 config that defines what the interceptor (ziti box) will intercept
    /// 3. a service that connects these configs
    /// 4. a bind policy that defines which identity binds this service (edge-router)
    /// 5. a dial policy that defines which identity dials this service (ziti box)
    #[allow(clippy::too_many_lines)]
    pub async fn create_edge_service(
        &self,
        ziti_box_id: String,
        address: String,
        ports: Vec<Port>,
        edge_router: &IdentityDetail,
    ) -> Result<(), ZitiApiError> {
        let zitibox = self.get_ziti_box(ziti_box_id).await?;
        let zitibox_name = zitibox.name;
        // creates a string like "443,2500-2505" from the ports parameter
        let ports_string = ports
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>()
            .join(",");
        let service_name = format!("{zitibox_name} {address} ({ports_string})");

        // Fetch host.v1 and intercept.v1 configs
        let mut types = list_config_types(&self.conf, None, None, None)
            .await?
            .data
            .into_iter();

        let host_v1 =
            types
                .find(|conf| conf.name == "host.v1")
                .ok_or(ZitiApiError::MalformedResponse(
                    "Response didn't contain a host.v1 configuration".to_owned(),
                ))?;

        let intercept_v1 = types.find(|conf| conf.name == "intercept.v1").ok_or(
            ZitiApiError::MalformedResponse(
                "Response didn't contain an intercept.v1 configuration".to_owned(),
            ),
        )?;

        // Create Host Config
        let host_v1_config = ConfigCreate {
            config_type_id: host_v1.id,
            name: format!("{service_name}-host"),
            // The data here is unformed since configs are too (consider creating structs for these)
            data: serde_json::from_value(json!({
                "forwardProtocol": true,
                "forwardAddress": true,
                "forwardPort": true,
                "allowedAddresses": [
                    address
                ],
                "allowedPortRanges": ports.iter().map(Value::from).collect::<Vec<Value>>(),
                // TODO: allow user to configure protocols
                "allowedProtocols": [
                    "tcp",
                    "udp"
                ],
                "httpChecks": [],
                "portChecks": []
            }))
            .map_err(|e| ZitiApiError::Other(Box::new(e)))?,
            ..Default::default()
        };
        let host_v1_config_id = create_config(&self.conf, host_v1_config)
            .await?
            .data
            .ok_or(ZitiApiError::MalformedResponse(
                "Response didn't contain data after host.v1 creation".to_owned(),
            ))?
            .id
            .ok_or(ZitiApiError::MalformedResponse(
                "Response didn't contain id in host.v1 data".to_owned(),
            ))?;

        // Create Intercept Config
        let intercept_v1_config = ConfigCreate {
            config_type_id: intercept_v1.id,
            name: format!("{service_name}-intercept"),
            data: serde_json::from_value(json!({
                "portRanges": ports.iter().map(Value::from).collect::<Vec<Value>>(),
                "addresses": [
                    address
                ],
                // TODO: allow user to configure protocols
                "protocols": [
                    "tcp",
                    "udp"
                ]
            }))
            .map_err(|e| ZitiApiError::Other(Box::new(e)))?,
            ..Default::default()
        };
        let intercept_v1_config_id = create_config(&self.conf, intercept_v1_config)
            .await?
            .data
            .ok_or(ZitiApiError::MalformedResponse(
                "Response didn't contain data after intercept.v1 creation".to_owned(),
            ))?
            .id
            .ok_or(ZitiApiError::MalformedResponse(
                "Response didn't contain id in intercept.v1 data".to_owned(),
            ))?;

        // Create Service
        let service = ServiceCreate {
            name: service_name.clone(),
            configs: Some(vec![host_v1_config_id, intercept_v1_config_id]),
            encryption_required: true,
            ..Default::default()
        };
        let service_id = create_service(&self.conf, service)
            .await?
            .data
            .ok_or(ZitiApiError::MalformedResponse(
                "Response didn't contain data after service creation".to_owned(),
            ))?
            .id
            .ok_or(ZitiApiError::MalformedResponse(
                "Response didn't contain id in service data".to_owned(),
            ))?;

        // Create Bind Policy
        let bind_policy = ServicePolicyCreate {
            name: format!("{service_name}-bind-policy"),
            // Our just created service
            service_roles: Some(vec![format!("@{service_id}")]),
            // The edge router
            identity_roles: Some(vec![format!("@{}", edge_router.id)]),
            r#type: DialBind::Bind,
            semantic: Semantic::AnyOf, // Debatable configuration
            ..Default::default()
        };
        create_service_policy(&self.conf, bind_policy).await?;

        // Create Dial Policy
        let dial_policy = ServicePolicyCreate {
            name: format!("{service_name}-dial-policy"),
            // Our just created service
            service_roles: Some(vec![format!("@{service_id}")]),
            // The edge router
            identity_roles: Some(vec![format!("@{}", zitibox.id)]),
            r#type: DialBind::Dial,
            semantic: Semantic::AnyOf, // Debatable configuration
            ..Default::default()
        };
        create_service_policy(&self.conf, dial_policy).await?;

        Ok(())
    }

    /// TODO: implement this to allow us to communicate over the OpenZiti network for ssh-ing into the ZitiBox
    pub async fn bootstrap_ziti_network(&self) -> Result<(), ZitiApiError> {
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

    /// Create an SSH session in the underlay newtork (plain non-Ziti networking)
    pub async fn ssh_underlay(&self) -> Result<(), ZitiApiError> {
        todo!()
    }
}

/// A port entry as used in the Ziti Service configs
#[derive(Debug, Clone)]
pub enum Port {
    /// A single port, e.g. 443 for https
    Single(u16),
    /// A range of ports, e.g. 1024–1048 for FTP in passive mode
    Range(u16, u16),
}

impl From<&Port> for Value {
    fn from(val: &Port) -> Self {
        match val {
            Port::Single(port) => json!({
                "high": port,
                "low": port
            }),
            Port::Range(start, end) => json!({
                "high": end,
                "low": start
            }),
        }
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(port) => write!(f, "{port}"),
            Self::Range(start, end) => write!(f, "{start}-{end}"),
        }
    }
}

/// This enum describes the enrollment state of an identity \
/// It exists for ergonomics reasons
#[derive(PartialEq, Eq)]
pub enum EnrollmentState {
    Enrolled,
    Expired,
    ReadyToEnroll {
        /// The number of minutes until this enrollment expires
        minutes_left: i64,
    },
    Unknown,
}

impl From<&IdentityEnrollments> for EnrollmentState {
    /// Takes a `ziti_api::IdentityEnrollments` and parses it into our own `EnrollmentState`\
    /// `EnrollmentState` is a lot more ergonomic for UI code
    fn from(enrollment: &IdentityEnrollments) -> Self {
        match enrollment {
            IdentityEnrollments { ott: None, .. } => Self::Enrolled,
            IdentityEnrollments { ott: Some(ott), .. } => {
                if let Some(date) = &ott.expires_at
                    && let Ok(ott_expiration) = date.parse::<DateTime<Utc>>()
                {
                    let minutes_left = (ott_expiration - Utc::now()).num_minutes();
                    if minutes_left > 0 {
                        Self::ReadyToEnroll { minutes_left }
                    } else {
                        Self::Expired
                    }
                } else {
                    Self::Unknown
                }
            }
        }
    }
}
