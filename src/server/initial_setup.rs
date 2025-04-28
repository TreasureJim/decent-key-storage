use std::future;

use anyhow::Context;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use lib::{
    connection::ConnectionError,
    key_storage::{KeyStorage, KeyStorageError},
    keys::key_fingerprint_b64,
    protocol::info::ServerInfo,
    HostPort,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error acquiring certificate: {0:?}")]
    Aquiring(ConnectionError),
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
    let mut certificate_futures = servers
        .into_iter()
        .map(|host| async move {
            let cert = lib::connection::connect_and_get_cert(&host).await;
            (*host, cert)
        })
        .collect::<FuturesUnordered<_>>();

    let info_futures = FuturesUnordered::new();

    while let Some((host, cert_result)) = certificate_futures.next().await {
        let cert = match cert_result {
            Ok(cert) => cert,
            Err(e) => return Err((host, Error::Aquiring(e))),
        };

        let fingerprint = key_fingerprint_b64(&*cert);
        if !confirm_fingerprint(&host.to_string(), &fingerprint).await {
            return Err((host, Error::NotMatching));
        }

        info_futures.push(async move {
            get_server_info(&host)
                .await
                .map(|info| (host.clone(), cert, info))
                .map_err(|e| (host, Error::Info(e)))
        });
    }

    info_futures
        .try_for_each(|(host, cert, server_info)| {
            future::ready(
                key_store
                    .add_certificate(server_info.uuid, cert, std::time::SystemTime::now())
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

async fn get_server_info(server: &HostPort) -> anyhow::Result<ServerInfo> {
    let mut client =
        lib::protocol::info::protocol::server_info_client::ServerInfoClient::connect(lib::to_endpoint(server)?)
            .await
            .context("Failed to connect to server")?;

    let response = client
        .get_server_info(tonic::Request::new(
            lib::protocol::info::protocol::ServerInfoRequest {},
        ))
        .await
        .context("Failed to get server info")?;

    Ok(response.into_inner().into())
}
