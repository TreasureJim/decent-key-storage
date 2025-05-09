use http::Uri;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use lib::{HostPort, protocol::proto::share_cert::cert_sharing_client::CertSharingClient};
use std::{net::SocketAddr, time::Duration};
use tonic::body::Body;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg()]
    server: SocketAddr,
    #[arg()]
    hz: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env).init();

    let args = Args::parse();
    lib::tls::initialize().expect("Couldn't initialise TLS");

    let request_per_sec = (1000.0 / args.hz as f64) as u64;
    println!("Making {} requests per second", args.hz);
    dbg!(&request_per_sec);

    let uri: Uri = HostPort::new(args.server).into();

    let duration = Duration::from_millis(request_per_sec);
    loop {
        let uri = uri.clone();
        tokio::spawn(async move {
            unsafe_query_network_for_uuid(uri).await;
        });
        
        tokio::time::sleep(duration).await;
    }
}

/// Connects to `n` multiple nodes in the network and queries them for a UUID's cert
/// Then cross references
pub async fn unsafe_query_network_for_uuid(
    uri: Uri
) {
    let client = lib::connection::dangerous_client();
    let mut client =
        lib::protocol::proto::share_cert::cert_sharing_client::CertSharingClient::with_origin(
            client,
            uri);

    let _ = client
        .get_certificates(tonic::Request::new(
            lib::protocol::proto::share_cert::RequestCertificates { uuids: vec![] },
        ))
        .await;
}
