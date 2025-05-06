#![feature(drain_keep_rest)]

mod connect_network;
mod query_network;
mod cross_ref;

use anyhow::anyhow;
use lib::{custom_tls::DebugHasKey, HostPort};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

use clap::Parser;

const DEFAULT_DATA_LOCATION: &str = "~/.local/decent-key-storage";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "ADDR", value_parser = HostPort::parse_arg)]
    server_addr: HostPort,
    #[arg(long, value_name = "FOLDER", default_value = DEFAULT_DATA_LOCATION, value_parser = lib::key_storage::canonicalize_path)]
    data_folder: PathBuf,
    #[arg(long, value_name = "ADDRESSES", value_parser = HostPort::parse_arg)]
    connect_network: Vec<HostPort>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("debug");
    env_logger::Builder::from_env(env).init();

    let args = Args::parse();

    let mut known_hosts = lib::key_storage::KeyStorage::new(args.data_folder)
        .expect("Error parsing known hosts file");

    lib::tls::initialize().expect("Couldn't initialise TLS");

    if args.connect_network.len() >= 2 {
        crate::connect_network::integrate_with_network(&mut known_hosts, &args.connect_network)
            .await?;
        log::info!("Network connection establish and keys downloaded.");
        return Ok(());
    }

    if known_hosts.amount_of_nodes() < 2 && args.connect_network.len() < 2 {
        return Err(anyhow!("ERROR: Network of nodes is not yet connected and connect-network argument not provided with 2 addresses."));
    }

    let known_hosts = Arc::new(RwLock::new(known_hosts));

    // CASES:
    // Want to connect to a client we know - use key store
    // Want to connect to a client we dont know - query many servers for its cert
    // Want to connect to a client we know but the client contacted has a different cert:
    //  - query other servers for what server is on this socket
    //  - ask the server who it is
    //  - obtain its certificate
    //  - check if info is correct -- PASS or FAIL

    let client = lib::connection::safe_client(known_hosts.read().await.snapshot());
    let mut share_certs_client =
        lib::protocol::proto::share_cert::cert_sharing_client::CertSharingClient::with_origin(
            client,
            (&args.server_addr).into(),
        );

    let certs = share_certs_client
        .get_certificates(tonic::Request::new(
            lib::protocol::proto::share_cert::RequestCertificates {
                uuids: vec![],
                sockets: vec![args.server_addr.to_string()],
            },
        ))
        .await?
        .into_inner();

    // TRUST ON FIRST USE MODEL

    // let mut client = greeter_client::new(channel);
    // let request = tonic::Request::new(EchoRequest {
    //     message: "hello".into(),
    // });

    // let response = client.unary_echo(request).await?;
    //
    // println!("RESPONSE={:?}", response);

    Ok(())
}
