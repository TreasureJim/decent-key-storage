use lib::{key_storage::KeyStorage, keys::{save_tonic_certificate, CertificateData}, HostPort};
use log::{info, warn};
use rand::seq::IteratorRandom;
use std::sync::Arc;
use uuid::Uuid;

use crate::{connect_network, cross_ref::cross_ref};

/// Given a key storage returns a maximum of `n` random known nodes sockets.
fn random_nodes(key_storage: &KeyStorage, n: usize) -> Vec<HostPort> {
    let mut rng = rand::rng();
    key_storage
        .get_all_node_info()
        .choose_multiple(&mut rng, n)
        .into_iter()
        .map(|node| node.sock_addr.into())
        .collect()
}

/// Checks local storage if a certificate for `uuid` is stored otherwise contacts `n` servers on
/// the network to retrieve and store the certificate
pub async fn query_for_uuid<'a>(
    key_storage: &'a mut KeyStorage,
    uuid: &Uuid,
    n: usize,
) -> Result<Arc<CertificateData>, connect_network::Error> {
    if let Some(cert) = key_storage.get_cert_data(uuid) {
        return Ok((*cert).clone());
    }

    let cert = query_network_for_uuid(key_storage, uuid, n).await?;
    save_tonic_certificate(key_storage, cert)?;
    Ok(key_storage.get_cert_data(uuid).unwrap().clone())
}

pub async fn query_and_update_uuid<'a>(
    key_storage: &'a mut KeyStorage,
    uuid: &Uuid,
    n: usize
) -> Result<Arc<CertificateData>, connect_network::Error> {
    let cert = query_network_for_uuid(key_storage, uuid, n).await?;
    save_tonic_certificate(key_storage, cert)?;
    Ok(key_storage.get_cert_data(uuid).unwrap().clone())
}

/// Connects to `n` multiple nodes in the network and queries them for a UUID's cert
/// Then cross references
pub async fn query_network_for_uuid<'a>(
    key_storage: &KeyStorage,
    uuid: &Uuid,
    n: usize,
) -> Result<
    lib::protocol::proto::share_cert::response_certificates::Certificate,
    connect_network::Error,
> {
    let client = lib::connection::safe_client(key_storage.snapshot());

    let responses = random_nodes(key_storage, n).into_iter().map(async |origin| -> Result<_, connect_network::Error> {
        let mut client = lib::protocol::proto::share_cert::cert_sharing_client::CertSharingClient::with_origin(client.clone(), origin.into());
        Ok(client.get_certificates(tonic::Request::new(
            lib::protocol::proto::share_cert::RequestCertificates {
                uuids: vec![uuid.to_string()]
            }
        )).await.map_err(|e| connect_network::Error::Connection(origin, e))?.into_inner())
    });
    let responses = futures::future::try_join_all(responses).await?;

    let cross_reference = cross_ref(responses);
    if cross_reference.len() > 1 {
        warn!(
            "Certificate mismatch detected: {} groups found",
            cross_reference.len()
        );
        return Err(connect_network::Error::CrossReference(cross_reference));
    }

    info!("All servers returned consistent certificates.");

    let cert = cross_reference
        .0
        .into_iter()
        .nth(0)
        .unwrap()
        .0
        .into_iter()
        .nth(0)
        .unwrap();
    Ok(cert)
}
