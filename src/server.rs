use flexible_hyper_server_tls::*;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use rustls::crypto::{ring, CryptoProvider};
use std::convert::Infallible;
use tokio::net::TcpListener;

async fn hello_world(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::<Bytes>::from("Hello, World!")))
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    println!("Listening on: {}", listener.local_addr().unwrap());

    let provider = ring::default_provider();
    rustls::crypto::CryptoProvider::install_default(provider).unwrap();
    let tls = rustls_helpers::get_tlsacceptor_from_files("./cert/cert.cer", "./cert/key.pem")
        .await
        .unwrap();

    let mut acceptor = HttpOrHttpsAcceptor::new(listener)
        .with_err_handler(|err| eprintln!("Error serving connection: {err:?}"))
        .with_tls(tls);

    loop {
        acceptor.accept(service_fn(hello_world)).await;
    }
}
