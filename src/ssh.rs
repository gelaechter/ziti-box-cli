//! This module contains the russh logic that lets us use SSH over OpenZiti using the ziti-sdk crate
//!
//! The idea is as follows:
//! For every command we want to execute remotely on the Ziti Box (wireshark and zfw) we generate one keypair
//! Then we generate and additional keypair that serves as the hosts public key ()
//! 

use color_eyre::eyre::{Result, bail};
use russh::{
    ChannelMsg, Disconnect, Preferred, client,
    keys::{PrivateKeyWithHashAlg, load_openssh_certificate, load_secret_key},
};
use std::{borrow::Cow, path::Path, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::ToSocketAddrs};

struct SSHClient {}

impl client::Handler for SSHClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // The plan is as follows
        // 1. Generate the keys as part of the image writing procss
        todo!()        
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct Session {
    session: client::Handle<SSHClient>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        user: impl Into<String>,
        openssh_cert_path: Option<P>,
        addrs: A,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, None)?;

        // load ssh certificate
        let openssh_cert = match openssh_cert_path {
            Some(path) => Some(load_openssh_certificate(path)?),
            None => None,
        };

        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            preferred: Preferred {
                kex: Cow::Owned(vec![
                    russh::kex::CURVE25519_PRE_RFC_8731,
                    russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                ]),
                ..Default::default()
            },
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = SSHClient {};

        let mut session = client::connect(config, addrs, sh).await?;

        // use publickey authentication, with or without certificate
        if let Some(cert) = openssh_cert {
            let auth_res = session
                .authenticate_openssh_cert(user, Arc::new(key_pair), cert)
                .await?;

            if !auth_res.success() {
                bail!("Authentication (with publickey+cert) failed");
            }
        } else {
            let auth_res = session
                .authenticate_publickey(
                    user,
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key_pair),
                        session.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;

            if !auth_res.success() {
                bail!("Authentication (with publickey) failed");
            }
        }

        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut code = None;
        let mut stdout = tokio::io::stdout();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    stdout.write_all(data).await?;
                    stdout.flush().await?;
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }
        Ok(code.expect("program did not exit cleanly"))
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}
