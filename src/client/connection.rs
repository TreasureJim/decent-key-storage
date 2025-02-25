use std::{net::{SocketAddr, ToSocketAddrs}, sync::Arc};
use thiserror::Error;

use http::Uri;

use crate::{channel::Channel, custom_tls, known_hosts::KnownHosts};

#[Error]
pub enum ConnectionError {
   // #[error()]
    
}

pub fn choose_connection<'a>(known_hosts: &'a KnownHosts, host_name: String) {
    
}

async fn tofu_connection(uri: Uri) -> Result<Channel, > {
    let ip = uri.host().expect("We should have checked for a valid host already").to_socket_addrs().unwrap_or(Vec::<SocketAddr>::new().into_iter()).next();
    
    let cert_capturer = custom_tls::CertTlsCapturer::new();
    let unsafe_tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(cert_capturer))
        .with_no_client_auth();

    let channel = Channel::new(&unsafe_tls_config, uri.clone())
        .await
        .expect("Trust on first use connection broken");
}

fn known_connection() {}
