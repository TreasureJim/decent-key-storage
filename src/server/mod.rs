mod initial_setup;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use lib::key_storage::{self, KeyStorage};
use lib::keys::{CertificateData, Identity};
use lib::protocol::info::ServerInfo;
use lib::protocol::server_state::ServerState;
use lib::HostPort;
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::Server;

use clap::Parser;

const DEFAULT_DATA_LOCATION: &str = "~/.local/decent-key-storage";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "FOLDER", default_value = DEFAULT_DATA_LOCATION, value_parser = lib::key_storage::canonicalize_path)]
    data_folder: PathBuf,
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:42000", value_parser = clap::value_parser!(SocketAddr))]
    client_addr: SocketAddr,
    #[arg(long, value_name = "ADDRESSES", value_parser = HostPort::parse_arg)]
    setup_network: Vec<HostPort>,
}

#[cfg(feature = "single_thread")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    println!("Running single-threaded runtime");
    run().await
}

#[cfg(not(feature = "single_thread"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

async fn run() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env).init();

    let args = Args::parse();

    lib::tls::initialize().unwrap();

    let identity = get_keys(&args.data_folder)?;

    let server_state = {
        let info = ServerInfo::load_or_create(
            args.data_folder.join(lib::protocol::info::SERVER_INFO_FILE),
        )
        .map_err(anyhow::Error::new)
        .context("Failed to load server info")?;

        let mut key_store = KeyStorage::create_with_backend(Box::new(
            key_storage::backend::FileStorageBackend::new(args.data_folder),
        ))
        .unwrap();
        key_store.add_certificate(
            info.uuid,
            CertificateData::from_pem(identity.cert.clone().into_inner())
                .context("Parsing this servers certificate")?,
            std::time::SystemTime::now(),
            args.client_addr,
        )?;

        ServerState::new(info, key_store)
    };

    let shutdown = Arc::new(tokio::sync::Notify::new());

    let mut server_handle: tokio::task::JoinHandle<Result<(), tonic::transport::Error>> = {
        let listener = tokio::net::TcpListener::bind(args.client_addr).await?;
        let shutdown_cpy = Arc::clone(&shutdown);
        let state_clone = Arc::clone(&server_state);
        tokio::spawn(async move {
            let local_addr = listener.local_addr().unwrap();

            log::info!("Listening on {:?}", local_addr);
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity.into()))?
                .add_service(lib::protocol::info::service::InformationService::server(
                    state_clone.clone(),
                ))
                .add_service(
                    lib::protocol::share_cert::service::ShareCertService::server(
                        state_clone.clone(),
                    ),
                )
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    shutdown_cpy.notified(),
                )
                .await?;
            Ok(())
        })
    };

    if !args.setup_network.is_empty() {
        initial_setup::contact_servers(
            &args.setup_network,
            &mut *server_state.key_store.write().await,
        )
        .await
        .map_err(|(addr, e)| {
            anyhow::Error::new(e).context(format!(
                "Failed to setup network. Failed on server: {}",
                addr
            ))
        })?;
    }

    // First wait for either CTRL+C or server to complete
    tokio::select! {
        res = &mut server_handle => {
            match &res {
                Ok(Ok(_)) => log::info!("Server shutdown cleanly"),
                Ok(Err(e)) => log::error!("Server exited with error: {:?}", e),
                Err(join_err) => log::error!("Server task panicked: {}", join_err),
            };
            return Ok(());
        }
        _ = tokio::signal::ctrl_c() => {
            log::info!("Received shutdown signal");
        }
    }

    // Then initiate graceful shutdown
    log::info!("Initiating graceful shutdown...");
    shutdown.notify_waiters();

    // Now wait for server to actually shutdown
    if !server_handle.is_finished() {
        match server_handle.await {
            Ok(Ok(_)) => log::info!("Server shutdown cleanly"),
            Ok(Err(e)) => log::error!("Server exited with error: {}", e),
            Err(join_err) => log::error!("Server task panicked: {}", join_err),
        };
    }

    Ok(())
}

fn get_keys(folder: &Path) -> anyhow::Result<Identity> {
    match Identity::read_from_folder(folder) {
        Ok(identity) => {
            log::debug!("Found existing self-signed keys in {:?}", folder);
            Ok(identity)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log::info!(
                "No existing keys found in {:?}, generating new self-signed keys",
                folder
            );
            let identity = Identity::generate();
            identity
                .save_to_folder(folder)
                .map_err(|e| anyhow::anyhow!("Failed to generate new keys: {}", e))?;
            Ok(identity)
        }
        Err(err) => {
            log::error!("Error reading keys from {:?}: {}", folder, err);
            Err(anyhow::anyhow!(
                "Could not read existing keys ({}). Please verify permissions or file integrity",
                err
            ))
        }
    }
}
