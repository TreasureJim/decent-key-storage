#![feature(drain_keep_rest)]

mod connect_network;
mod query_network;

use lib::{custom_tls::DebugHasKey, HostPort};
use std::{path::PathBuf, sync::Arc};
use anyhow::anyhow;

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
    let args = Args::parse();

    let known_hosts = lib::key_storage::KeyStorage::new(
        args.data_folder
    )
    .expect("Error parsing known hosts file");
    let known_hosts = Arc::new(known_hosts);
    let has_key: Arc<dyn DebugHasKey> = known_hosts.clone() as Arc<dyn DebugHasKey>;

    lib::tls::initialize().expect("Couldn't initialise TLS");

    if args.connect_network.len() >= 2 {
        todo!("Connect to network and fill key storage");
    }

    if known_hosts.amount_of_nodes() < 2 && args.connect_network.len() < 2 {
        return Err(anyhow!("ERROR: Network of nodes is not yet connected and connect-network argument not provided with 2 addresses."));
    }

    // CASES:
    // Want to connect to a client we know - use key store
    // Want to connect to a client we dont know - query many servers for its cert
    // Want to connect to a client we know but the client contacted has a different cert:
    //  - query other servers for what server is on this socket
    //  - ask the server who it is
    //  - obtain its certificate
    //  - check if info is correct -- PASS or FAIL

    let client = lib::connection::safe_client(Arc::clone(&has_key));

    let mut share_certs_client = lib::protocol::proto::share_cert::cert_sharing_client::CertSharingClient::with_origin(client, (&args.server_addr).into());

    let certs = share_certs_client.get_certificates(tonic::Request::new(
        lib::protocol::proto::share_cert::RequestCertificates {}
    )).await?;

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
