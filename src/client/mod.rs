#![feature(drain_keep_rest)]
#![feature(let_chains)]

mod connect_network;
mod cross_ref;
mod query_network;

use anyhow::anyhow;
use lib::{
    key_storage::{self, KeyStorage},
    HostPort,
};
use std::path::PathBuf;
use uuid::Uuid;

use clap::Parser;

const DEFAULT_DATA_LOCATION: &str = "~/.local/decent-key-storage";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "ADDR")]
    server_uuid: Uuid,
    #[arg(long, value_name = "FOLDER", default_value = DEFAULT_DATA_LOCATION, value_parser = lib::key_storage::canonicalize_path)]
    data_folder: PathBuf,
    #[arg(long, value_name = "ADDRESSES", value_delimiter=',', value_parser = HostPort::parse_arg)]
    connect_network: Vec<HostPort>,
    #[arg(long, short)]
    query_network: bool,
    #[arg()]
    n: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("debug");
    env_logger::Builder::from_env(env).init();

    let args = Args::parse();

    let mut known_hosts = KeyStorage::create_with_backend(Box::new(
        key_storage::backend::FileStorageBackend::new(args.data_folder),
    ))
    .unwrap();

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

    // CASES:

    // Want to connect to a client we know - use key store
    if !args.query_network
        && let Some(cert_data) = known_hosts.get_certificate_uuid(&args.server_uuid)
    {
        println!("Found server locally:");
        println!("{:?}", cert_data);
        return Ok(());
    }

    // Want to connect to a client we dont know - query many servers for its cert
    println!("Querying network...");
    if args.query_network {
        query_network::query_and_update_uuid(&mut known_hosts, &args.server_uuid, args.n).await?;
        if let Some(cert_data) = known_hosts.get_certificate_uuid(&args.server_uuid) {
            println!("Retrieved server from network:");
            println!("{:?}", cert_data);
            return Ok(());
        }
    }

    query_network::query_network_for_uuid(&mut known_hosts, &args.server_uuid, args.n).await?;
    if let Some(cert_data) = known_hosts.get_certificate_uuid(&args.server_uuid) {
        println!("Retrieved server from network:");
        println!("{:?}", cert_data);
    }

    Ok(())
}
