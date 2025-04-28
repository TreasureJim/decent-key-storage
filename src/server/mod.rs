mod initial_setup;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use lib::protocol::info::ServerInfo;
use lib::protocol::server_state::ServerState;
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::Identity;
use tonic::transport::Server;

use clap::Parser;

const DEFAULT_DATA_LOCATION: &str = "~/.local/decent-key-storage";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "FOLDER", default_value = DEFAULT_DATA_LOCATION, value_parser = canonicalize_path)]
    data_folder: PathBuf,
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:42000", value_parser = clap::value_parser!(SocketAddr))]
    client_addr: SocketAddr,
    #[arg(long, value_name = "ADDRESSES")]
    setup_network: Vec<SocketAddr>,
}

fn canonicalize_path(path: &str) -> Result<PathBuf, anyhow::Error> {
    let expanded = expanduser::expanduser(path)?;
    Ok(expanded)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        // .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    lib::tls::initialize().unwrap();

    let server_state = {
        let info = ServerInfo::load_or_create(
            args.data_folder.join(lib::protocol::info::SERVER_INFO_FILE),
        )
        .map_err(anyhow::Error::new)
        .context("Failed to load server info")?;

        let key_store = lib::key_storage::KeyStorage::new(&args.data_folder)
            .context("Failed to initialize key storage")?;

        ServerState::new(info, key_store)
    };

    let shutdown = Arc::new(tokio::sync::Notify::new());

    let mut server_handle: tokio::task::JoinHandle<Result<(), tonic::transport::Error>> = {
        let listener = tokio::net::TcpListener::bind(args.client_addr).await?;
        let identity = get_keys(&args.data_folder)?;
        let shutdown_cpy = Arc::clone(&shutdown);
        let state_clone = Arc::clone(&server_state);
        tokio::spawn(async move {
            let local_addr = listener.local_addr().unwrap();

            log::info!("Listening on {:?}", local_addr);
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity))?
                .add_service(lib::protocol::info::service::InformationService::server(
                    state_clone,
                ))
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
    match lib::key_storage::read_self_signed_keys(folder) {
        Ok(identity) => {
            log::debug!("Found existing self-signed keys in {:?}", folder);
            Ok(identity)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log::info!(
                "No existing keys found in {:?}, generating new self-signed keys",
                folder
            );
            lib::key_storage::create_self_signed_keys(folder)
                .map_err(|e| anyhow::anyhow!("Failed to generate new keys: {}", e))
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
