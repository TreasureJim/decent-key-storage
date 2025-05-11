use anyhow::Context;
use chrono::Utc;
use http::Uri;
use lib::HostPort;
use log::{error, info};
use std::{
    fs::File,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::{
    select,
    sync::{
        Mutex,
        mpsc::{UnboundedReceiver, UnboundedSender},
    },
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tonic::Code;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_parser = parse_duration)]
    poll_time: Option<Duration>,
    #[arg()]
    server: SocketAddr,
    #[arg()]
    hz: usize,
    #[arg()]
    perf_hz: usize,
    #[arg()]
    output: PathBuf,
    #[arg()]
    process: String,
    #[arg(last = true)]
    process_args: Vec<String>,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env).init();

    let args = Args::parse();
    lib::tls::initialize().expect("Couldn't initialise TLS");

    info!("Spawning: {} {:?}", args.process, args.process_args);
    let mut child = Command::new(&args.process)
        .args(&args.process_args)
        // .stdout(Stdio::null())
        // .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn child process");
    let pid = child.id();
    info!("Child PID: {}", pid);

    let uri: Uri = HostPort::new(args.server).into();
    // Test network
    {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let resp = unsafe_query_network_for_uuid(uri.clone()).await.context("Failed to make test connection");
        if resp.is_err() {
            child.kill()?;
            resp?;
        }
    }

    let stop = CancellationToken::new();

    let perf_file = args.output.join(format!("performance_{}.csv", args.hz));
    let perf_writer = Arc::new(Mutex::new(csv::Writer::from_path(perf_file)?));
    let writer_clone = perf_writer.clone();
    let stop_clone = stop.clone();
    let perf_handle =
        tokio::spawn(
            async move { log_performance(pid, args.perf_hz, writer_clone, stop_clone).await },
        );

    info!("Making {} requests per second", args.hz);
    let (handle_tx, handle_rx) = tokio::sync::mpsc::unbounded_channel();

    let responses_file = args.output.join(format!("responses_{}.csv", args.hz));
    let responses_writer = Arc::new(Mutex::new(csv::Writer::from_path(responses_file)?));
    let writer_clone = responses_writer.clone();
    let stop_clone = stop.clone();
    let rec_handle =
        tokio::spawn(async move { log_handles(handle_rx, writer_clone, stop_clone).await });

    select! {
        err = ddos(args.hz, uri, handle_tx) => {
            error!("{err:?}");
        }
        err = perf_handle => {
            error!("{err:?}");
        }
        err = rec_handle => {
            error!("{err:?}");
        }
        _ = tokio::signal::ctrl_c() => {
            log::info!("Received shutdown signal");
        }
        _ = tokio::time::sleep(args.poll_time.unwrap()), if args.poll_time.is_some() => {
            log::info!("Timer finished");
        }
    };

    stop.cancel();

    // Cleanup
    info!("Killing child!");
    child.kill()?;
    info!("Writing performance file!");
    let _ = perf_writer.lock().await.flush();
    info!("Writing responses file!");
    let _ = responses_writer.lock().await.flush();

    Ok(())
}

async fn ddos(
    hz: usize,
    uri: Uri,
    handle_tx: UnboundedSender<JoinHandle<bool>>,
) -> anyhow::Result<()> {
    let duration = Duration::from_millis((1000.0 / hz as f64) as u64);
    loop {
        let uri = uri.clone();
        let handle = tokio::spawn(async move {
            let response = unsafe_query_network_for_uuid(uri).await;
            if let Err(e) = response {
                match e.code() {
                    Code::Unavailable | Code::Internal | Code::DataLoss => {
                        return false;
                    }
                    _ => {
                        return true;
                    }
                }
            }
            true
        });
        handle_tx.send(handle).context("Sending handle")?;

        tokio::time::sleep(duration).await;
    }
}

/// Connects to `n` multiple nodes in the network and queries them for a UUID's cert
/// Then cross references
async fn unsafe_query_network_for_uuid(
    uri: Uri,
) -> Result<tonic::Response<lib::protocol::proto::share_cert::ResponseCertificates>, tonic::Status>
{
    let client = lib::connection::dangerous_client();
    let mut client =
        lib::protocol::proto::share_cert::cert_sharing_client::CertSharingClient::with_origin(
            client, uri,
        );

    client
        .get_certificates(tonic::Request::new(
            lib::protocol::proto::share_cert::RequestCertificates { uuids: vec![] },
        ))
        .await
}

async fn log_handles(
    mut handle_rx: UnboundedReceiver<JoinHandle<bool>>,
    writer: Arc<Mutex<csv::Writer<File>>>,
    stop: CancellationToken,
) -> anyhow::Result<()> {
    let mut writer = writer.lock().await;
    writer.write_record(&["received_at".to_string(), "success".to_string()])?;

    let mut futures = futures::stream::futures_unordered::FuturesUnordered::new();

    loop {
        select! {
            handle = handle_rx.recv() => {
                if let Some(handle) = handle {
                    futures.push(handle);
                }
            }
            finished = futures.next() => {
                match finished {
                    Some(Ok(true)) => {
                        writer.write_record(&[Utc::now().to_rfc3339(), true.to_string()])?;
                    }
                    Some(Ok(false)) => {
                        writer.write_record(&[Utc::now().to_rfc3339(), false.to_string()])?;
                    }
                    _ => {}
                }
            }
            _ = stop.cancelled() => {
                break;
            }
        }
    }

    Ok(())
}

async fn log_performance(
    pid: u32,
    poll_frequency: usize,
    writer: Arc<Mutex<csv::Writer<File>>>,
    stop: CancellationToken,
) -> anyhow::Result<()> {
    let mut writer = writer.lock().await;
    writer.write_record(&[
        "timestamp".to_string(),
        "cpu".to_string(),
        "mem".to_string(),
    ])?;

    let sleep_duration = Duration::from_millis((1000.0 / poll_frequency as f64) as u64);
    let mut sys = System::new_all();
    let pid = sysinfo::Pid::from_u32(pid as u32);

    loop {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid.into()]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        if let Some(proc) = sys.process(pid) {
            let ts = Utc::now().to_rfc3339();
            let cpu = proc.cpu_usage();
            let mem = proc.memory();

            writer.write_record(&[ts, format!("{:.2}", cpu), mem.to_string()])?;
        } else {
            info!("Process {} not found (maybe exited)", pid);
            break;
        }

        if stop.is_cancelled() {
            break;
        }
        tokio::time::sleep(sleep_duration).await;
    }

    let _ = writer.flush();

    Ok(())
}
