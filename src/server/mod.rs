use lib::tls::initialize;
use std::net::SocketAddr;
use std::path::PathBuf;

use tonic::transport::Identity;
use tonic::{transport::Server, Request, Response, Status};
use tonic::transport::server::ServerTlsConfig;

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "FOLDER", default_value = lib::key_storage::DEFAULT_DATA_LOCATION, value_parser = clap::value_parser!(PathBuf))]
    data_folder: PathBuf,
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:0", value_parser = clap::value_parser!(SocketAddr))]
    client_addr: SocketAddr,
}

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[derive(Debug, Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = HelloReply {
            message: format!("Hello {}", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let listener = tokio::net::TcpListener::bind(args.client_addr).await?;
    println!("Listening on {:?}", listener.local_addr().unwrap());

    let cert = {
        let mut path = args.data_folder.clone();
        path.push("cert.pem");
        std::fs::read_to_string(path)?
    };
    let key = {
        let mut path = args.data_folder.clone();
        path.push("key.pem");
        std::fs::read_to_string(path)?
    };

    initialize().expect("Couldn't initialise encryption");
    let identity = Identity::from_pem(cert, key);

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(GreeterServer::new(MyGreeter::default()))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await?;

    // TODO: Wait for first thread to crash and then cleanly shutdown the other threads
    // Use select! {}

    Ok(())
}
