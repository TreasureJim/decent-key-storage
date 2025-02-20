mod channel;
mod known_hosts;
mod custom_tls;
mod global;

pub mod pb {
    tonic::include_proto!("helloworld");
}

use http::Uri;
use std::{fs::read_to_string, path::PathBuf, sync::Arc};

use clap::Parser;

use channel::Channel;
use pb::greeter_client;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "FILE")]
    known_hosts: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let known_hosts_path = args
        .known_hosts
        .or_else(|| {
            Some(
                known_hosts::default_known_hosts_file()
                    .expect("Could not find default known hosts location")
                    .to_path_buf(),
            )
        })
        .unwrap();
    let known_hosts = known_hosts::KnownHosts::deserialise_known_hosts(read_to_string(known_hosts_path).expect("Could not open known hosts file"));

    custom_tls::initialize().expect("Couldn't initialise TLS");

    let cert_capturer = custom_tls::CertTlsCapturer::new();
    let unsafe_tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(cert_capturer))
        .with_no_client_auth();

    let channel = Channel::new(&unsafe_tls_config, "hello.com".parse::<Uri>().unwrap());

    // let mut client = greeter_client::new(channel);
    // let request = tonic::Request::new(EchoRequest {
    //     message: "hello".into(),
    // });

    // let response = client.unary_echo(request).await?;
    //
    // println!("RESPONSE={:?}", response);

    Ok(())
}
