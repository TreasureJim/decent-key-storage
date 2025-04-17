use futures::stream::FuturesUnordered;
use http::Uri;
use lib::{connection::ConnectionError, key_storage::KeyStorage, keys::key_fingerprint_b64, HostPort};
use tokio_stream::StreamExt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error acquiring certificate: {0:?}")]
    Aquiring(ConnectionError),
    #[error("Certificates were not matching")]
    NotMatching
}

/// Connects to the list of servers given, confirms with user if the keys are valid.
/// If Invalid it will return the Uri of the bad server
/// Stores all valid keys in the key store
pub async fn contact_servers(
    servers: Vec<HostPort>,
    key_store: &mut KeyStorage,
) -> Result<(), (HostPort, Error)> {
    let mut futures = servers
        .into_iter()
        .map(|host| async move {
            let res = lib::connection::connect_and_get_cert(&host).await;
            (host, res)
        })
        .collect::<FuturesUnordered<_>>();

    while let Some((host, cert)) = futures.next().await {
        let cert = match cert {
            Ok(cert) => cert,
            Err(e) => return Err((host, Error::Aquiring(e))),
        };

        loop {
            println!(
                "Key fingerprint from {:?} is {:?}\nDoes this fingerprint match? (y)es/(n)o",
                &host.host,
                key_fingerprint_b64(&cert.public_key)
            );

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            match input.trim_end() {
                "y" | "yes" => {
                    key_store.add_host(host.host, cert);
                    break;
                }
                "n" | "no" => {
                    return Err((host, Error::NotMatching));
                }
                _ => {
                    continue;
                }
            }
        }
    }

    Ok(())
}
