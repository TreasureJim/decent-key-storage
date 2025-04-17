/* pub mod pb {
    tonic::include_proto!("helloworld");
}

use http::Uri;
use std::{fs::read_to_string, path::PathBuf, sync::Arc};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    uri: Uri,
    #[arg(long, value_name = "FILE")]
    known_hosts: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    args.uri.host().expect("uri needs to contain a valid hostname");

    let known_hosts_path = args
        .known_hosts
        .or_else(|| {
            Some(
                lib::key_storage::default_storage_file()
                    .expect("Could not find default known hosts location")
                    .to_path_buf(),
            )
        })
        .unwrap();
    let known_hosts = lib::key_storage::KeyStorage::deserialise_hosts(
        read_to_string(known_hosts_path).expect("Could not open known hosts file"),
    )
    .expect("Error parsing known hosts file");

    lib::tls::initialize().expect("Couldn't initialise TLS");

    let known_host_tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(lib::custom_tls::KnownHostsTls::new(
            known_hosts.get_host_keys(args.uri.to_string()),
        )))
        .with_no_client_auth();

    let channel = Channel::new(&known_host_tls_config, args.uri.clone())
        .await
        .expect("Known hosts connection broken");
    let mut greeter_client = pb::greeter_client::GreeterClient::new(channel.clone());

    greeter_client
        .say_hello(pb::HelloRequest {
            name: "Liam".to_string(),
        })
        .await
        .unwrap();

    // TRUST ON FIRST USE MODEL

    let mut greeter_client = pb::greeter_client::GreeterClient::new(channel.clone());

    let r = greeter_client
        .say_hello(pb::HelloRequest {
            name: "Liam".to_string(),
        })
        .await
        .unwrap();

    println!("{:?}", r);

    // let mut client = greeter_client::new(channel);
    // let request = tonic::Request::new(EchoRequest {
    //     message: "hello".into(),
    // });

    // let response = client.unary_echo(request).await?;
    //
    // println!("RESPONSE={:?}", response);

    Ok(())
} */

fn main() {
    todo!();
}
