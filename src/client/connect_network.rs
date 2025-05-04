use thiserror::Error;
use std::collections::{HashMap, HashSet};
use std::future::Future;

use anyhow::Context;
use futures::StreamExt;
use lib::protocol::proto::share_cert::RequestCertificates;
use lib::protocol::proto::share_cert::{
    self, response_certificates::Certificate, ResponseCertificates,
};

use lib::{key_storage, HostPort};
use uuid::Uuid;

async fn try_collect_async<C, E>(
    iter: impl Iterator<Item = impl Future<Output = Result<C, E>>>,
) -> Result<Vec<C>, E> {
    let mut futures = iter.collect::<futures::stream::FuturesUnordered<_>>();

    let mut results = Vec::new();
    while let Some(result) = futures.next().await {
        match result {
            Ok(c) => {
                results.push(c);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(results)
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not connect to {0}")]
    Connection(HostPort),
    #[error("Conflicting key references were found")]
    CrossReference
}

pub async fn connect_network(
    key_storage: &mut key_storage::KeyStorage,
    servers: &[HostPort],
) -> anyhow::Result<()> {
    assert!(servers.len() >= 2);

    // Connect to all servers
    let client = lib::connection::dangerous_client();

    let lol_certs = servers.iter().map(async |server| {
        let mut cert_client = share_cert::cert_sharing_client::CertSharingClient::with_origin(
            client.clone(),
            server.into(),
        );

        cert_client
            .get_certificates(tonic::Request::new(RequestCertificates {}))
            .await
    });
    let lol_certs = try_collect_async(lol_certs)
        .await
        .context("Failed to connect to server")?
        .into_iter()
        .map(|response| response.into_inner())
        .collect::<Vec<_>>();

    // Cross reference
    let cross_reference = cross_ref(&lol_certs);
    if cross_reference.len() > 1 {
        
    }

    // Report any inconsistencies
    // Save to key storage
    todo!();
}

fn cross_ref(lol_certs: &[ResponseCertificates]) -> Vec<(HashSet<&Certificate>, Vec<Uuid>)> {
    let mut groups = Vec::new();
    let mut iter = lol_certs.iter();

    fn create_set<'a>(server_resp: &'a ResponseCertificates) -> HashSet<&'a Certificate> {
        let mut set = HashSet::new();

        for cert in &server_resp.certificates {
            set.insert(cert);
        }

        set
    }

    {
        let first = iter.next().unwrap();
        groups.push((
            create_set(first),
            vec![first
                .uuid
                .parse::<Uuid>()
                .expect("Server gave invalid uuid")],
        ))
    }
    let mut current_group = &mut groups[0];

    for child in iter {
        if response_certs_match(&current_group.0, &child) {
            current_group.1.push(child.uuid.parse::<Uuid>().unwrap());
        } else {
            groups.push((
                create_set(&child),
                vec![child.uuid.parse::<Uuid>().unwrap()],
            ));
            current_group = groups.last_mut().unwrap();
        }
    }

    groups
}

/// Checks that the certificates
fn response_certs_match(set: &HashSet<&Certificate>, response: &ResponseCertificates) -> bool {
    for cert in &response.certificates {
        if !set.contains(cert) {
            return false;
        }
    }

    true
}
