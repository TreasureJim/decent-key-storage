use std::{future, sync::Arc, time::Duration};

use anyhow::Context;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use lib::{
    connection::ConnectionError,
    key_storage::{KeyStorage, KeyStorageError},
    keys::{key_fingerprint_b64, CertificateData, HasKey},
    protocol::info::ServerInfo,
    HostPort,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error acquiring certificate: {0:?}")]
    Aquiring(#[from] ConnectionError),
    #[error("Certificates were not matching")]
    NotMatching,
    #[error("Error retreiving server info: {0:?}")]
    Info(anyhow::Error),
    #[error("{0:?}")]
    SavingCert(#[from] KeyStorageError),
}

/// Connects to the list of servers given, confirms with user if the keys are valid.
/// If Invalid it will return the Uri of the bad server
/// Stores all valid keys in the key store
pub async fn contact_servers(
    servers: &[HostPort],
    key_store: &mut KeyStorage,
) -> Result<(), (HostPort, Error)> {
    const RETRY_ATTEMPTS: u8 = 5;
    const RETRY_DELAY: Duration = Duration::from_secs(5);

    let connect_with_timeout = |(host, attempt, timeout)| async move {
        tokio::time::sleep(timeout).await;
        let cert = lib::connection::connect_and_get_cert(&host).await;
        (host, attempt, cert)
    };

    let mut certificate_futures = servers
        .into_iter()
        .map(|host| (*host, 1, Duration::ZERO))
        .map(connect_with_timeout)
        .collect::<FuturesUnordered<_>>();

    let info_futures = FuturesUnordered::new();

    while let Some((host, attempt, cert_result)) = certificate_futures.next().await {
        let cert = match cert_result {
            Ok(cert) => cert,
            Err(ConnectionError::Connection(e)) => {
                if attempt > RETRY_ATTEMPTS {
                    return Err((host, Error::Aquiring(ConnectionError::Connection(e))));
                }

                certificate_futures.push(connect_with_timeout((host, attempt + 1, RETRY_DELAY)));

                continue;
            }
            Err(e) => return Err((host, Error::Aquiring(e))),
        };

        // Confirm fingerprint with user
        let fingerprint = key_fingerprint_b64(&*cert);
        if !confirm_fingerprint(&host.to_string(), &fingerprint).await {
            return Err((host, Error::NotMatching));
        }

        // Add task to get the server info to queue
        info_futures.push(async move {
            get_server_info(&host, &cert)
                .await
                .map(|info| (host.clone(), cert, info))
                .map_err(|e| (host, Error::Info(e)))
        });
    }

    info_futures
        .try_for_each(|(host, cert, server_info)| {
            future::ready(
                key_store
                    .add_certificate(server_info.uuid, cert, std::time::SystemTime::now(), host.addr)
                    .map_err(|e| (host, Error::SavingCert(e))),
            )
        })
        .await?;

    println!("All servers verified successfully!");
    Ok(())
}

async fn confirm_fingerprint(host: &str, fingerprint: &str) -> bool {
    loop {
        println!(
            "Key fingerprint from {:?} is {:?}\nDoes this fingerprint match? (y)es/(n)o",
            host, fingerprint
        );

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => {
                println!("Please answer with 'y' or 'n'");
                continue;
            }
        }
    }
}
#[derive(Debug)]
struct SingleKey(CertificateData);
impl HasKey for SingleKey {
    fn have_tonic_certificate(&self, cert: &tonic::transport::CertificateDer<'_>) -> bool {
        *self.0.raw() == *cert.as_ref()
    }
}

async fn get_server_info(server: &HostPort, cert: &CertificateData) -> anyhow::Result<ServerInfo> {
    let single_key = Arc::new(SingleKey(cert.clone()));

    let client = lib::connection::safe_client(single_key);

    let mut client =
        lib::protocol::proto::info::server_info_client::ServerInfoClient::with_origin(client, server.into());

    let response = client
        .get_server_info(tonic::Request::new(
            lib::protocol::proto::info::ServerInfoRequest {},
        ))
        .await
        .context("Failed to get server info")?;

    Ok(response.into_inner().into())
}
