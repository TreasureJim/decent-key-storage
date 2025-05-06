use std::collections::HashSet;
use lib::protocol::proto::share_cert::{response_certificates::Certificate, ResponseCertificates};
use uuid::Uuid;
use log::{debug, warn};

use crate::connect_network::CrossReferencedCertificates;

pub fn cross_ref(lol_certs: Vec<ResponseCertificates>) -> CrossReferencedCertificates {
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
