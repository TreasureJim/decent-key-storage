mod initial_setup;

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::Identity;
use tonic::{transport::Server, Request, Response, Status};

use clap::Parser;

const DEFAULT_DATA_LOCATION: &str = "~/.local/decent-key-storage";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "FOLDER", default_value = DEFAULT_DATA_LOCATION, value_parser = clap::value_parser!(PathBuf))]
    data_folder: PathBuf,
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:0", value_parser = clap::value_parser!(SocketAddr))]
    client_addr: SocketAddr,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    lib::tls::initialize().unwrap();

    let shutdown = Arc::new(tokio::sync::Notify::new());

    let mut server_handle = {
        let listener = tokio::net::TcpListener::bind(args.client_addr).await?;
        let identity = get_keys(&args.data_folder)?;
        let shutdown_cpy = Arc::clone(&shutdown);
        tokio::spawn(async move {
            run_server(identity, listener, shutdown_cpy.notified()).await
        })
    };

    // First wait for either CTRL+C or server to complete
    tokio::select! {
        res = &mut server_handle => {
            if let Err(e) = res {
                log::error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            log::info!("Received shutdown signal");
        }
    }

    // Then initiate graceful shutdown
    log::info!("Initiating graceful shutdown...");
    shutdown.notify_waiters();

    // Now wait for server to actually shutdown
    match server_handle.await {
        Ok(Ok(_)) => log::info!("Server shutdown cleanly"),
        Ok(Err(e)) => log::error!("Server exited with error: {}", e),
        Err(join_err) => log::error!("Server task panicked: {}", join_err),
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

async fn run_server(
    identity: tonic::transport::Identity,
    listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let local_addr = listener.local_addr().unwrap();

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(GreeterServer::new(MyGreeter::default()))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    log::info!("Listening on {:?}", local_addr);
    Ok(())
}
