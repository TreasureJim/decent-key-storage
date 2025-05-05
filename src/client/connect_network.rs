use std::collections::HashSet;
use std::fmt::Display;
use thiserror::Error;

use futures::StreamExt;
use lib::protocol::proto::share_cert::RequestCertificates;
use lib::protocol::proto::share_cert::{
    self, response_certificates::Certificate, ResponseCertificates,
};

use itertools::Itertools;
use lib::{key_storage, HostPort};
use uuid::Uuid;
use log::{debug, error, info, warn};

#[derive(Debug)]
pub struct CrossReferencedCertificates(Vec<(HashSet<Certificate>, Vec<Uuid>)>);

impl std::ops::Deref for CrossReferencedCertificates {
    type Target = Vec<(HashSet<Certificate>, Vec<Uuid>)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for CrossReferencedCertificates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, group) in self.0.iter().enumerate() {
            writeln!(f, "Group {}:", i + 1)?;
            write!(f, "{}", group.1.iter().format(", "))?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not connect to {0}: {1}")]
    Connection(HostPort, tonic::Status),
    #[error("Conflicting key references were found. The following groups of certificate hosts were found: {0}")]
    CrossReference(CrossReferencedCertificates),
    #[error("Failed to save certificate: {0}")]
    SavingCertificate(#[from] anyhow::Error),
}

pub async fn connect_network(
    key_storage: &mut key_storage::KeyStorage,
    servers: &[HostPort],
) -> Result<(), Error> {
    assert!(servers.len() >= 2);

    info!("Connecting to {} servers...", servers.len());
    let client = lib::connection::dangerous_client();

    let lol_certs = servers.iter().map(async |server| {
        info!("Requesting certificates from {}", server);
        let mut cert_client = share_cert::cert_sharing_client::CertSharingClient::with_origin(
            client.clone(),
            server.into(),
        );

        match cert_client
            .get_certificates(tonic::Request::new(RequestCertificates {}))
            .await
        {
            Ok(response) => {
                debug!("Received certificates from {}", server);
                Ok(response)
            }
            Err(e) => {
                error!("Failed to get certificates from {}: {}", server, e);
                Err(Error::Connection(*server, e))
            }
        }
    });

    let lol_certs = futures::future::try_join_all(lol_certs)
        .await?
        .into_iter()
        .map(|response| response.into_inner())
        .collect::<Vec<_>>();

    info!("Received certificates from all servers");

    let cross_reference = cross_ref(lol_certs);

    if cross_reference.len() > 1 {
        warn!(
            "Certificate mismatch detected: {} groups found",
            cross_reference.len()
        );
        return Err(Error::CrossReference(cross_reference));
    }

    info!("All servers returned consistent certificates. Saving...");

    for cert in cross_reference.0.into_iter().nth(0).unwrap().0.into_iter() {
        debug!("Saving certificate: {:?}", cert);
        lib::keys::save_tonic_certificate(key_storage, cert)?;
    }

    info!("All certificates saved successfully.");
    Ok(())
}

fn cross_ref(lol_certs: Vec<ResponseCertificates>) -> CrossReferencedCertificates {
    let mut groups = Vec::new();
    let mut iter = lol_certs.into_iter();

    let create_set = |ResponseCertificates { uuid, certificates }| {
        (
            certificates.into_iter().collect::<HashSet<_>>(),
            vec![uuid.parse::<Uuid>().expect("Server gave invalid uuid")],
        )
    };

    {
        let first = iter.next().unwrap();
        groups.push(create_set(first));
    }

    let mut current_group = &mut groups[0];

    for child in iter {
        if response_certs_match(&current_group.0, &child) {
            debug!("Response from {} matched current group", child.uuid);
            current_group.1.push(child.uuid.parse::<Uuid>().unwrap());
        } else {
            warn!("Response from {} did not match current group", child.uuid);
            groups.push(create_set(child));
            current_group = groups.last_mut().unwrap();
        }
    }

    CrossReferencedCertificates(groups)
}

fn response_certs_match(set: &HashSet<Certificate>, response: &ResponseCertificates) -> bool {
    if set.len() != response.certificates.len() {
        return false;
    }

    response.certificates.iter().all(|cert| set.contains(cert))
}
