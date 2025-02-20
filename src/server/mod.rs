use std::net::SocketAddr;

use tonic::transport::Identity;
use tonic::{transport::Server, Request, Response, Status};
use tonic::transport::server::ServerTlsConfig;

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};

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
    let addr = std::env::args().into_iter().skip(1).next().unwrap_or("0.0.0.0:0".to_string());
    let addr = addr.parse::<SocketAddr>()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Listening on {:?}", listener.local_addr().unwrap());

    let cert = std::fs::read_to_string("cert/cert.cer")?;
    let key = std::fs::read_to_string("cert/key.pem")?;

    let identity = Identity::from_pem(cert, key);

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(GreeterServer::new(MyGreeter::default()))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await?;

    Ok(())
}
