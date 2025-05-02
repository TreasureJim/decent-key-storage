use lib::protocol::proto::share_cert;

use lib::{key_storage, HostPort};

pub fn connect_network(key_storage: &mut key_storage::KeyStorage, servers: &[HostPort]) {
    // Connect to all servers
    let client = lib::connection::dangerous_client();

    servers.iter().map(|server| {
        let cert_client = share_cert::cert_sharing_client::CertSharingClient::with_origin(client.clone(), server.into());
        cert_client.get_certificates(tonic::Request::new(share_cert::RequestCertificates {}))
    })

    // Cross reference
    cross_ref();
    // Report any inconsistencies
    // Save to key storage
    todo!();
}

fn cross_ref() {
    // for certs in rec_certs:
    //  
}
