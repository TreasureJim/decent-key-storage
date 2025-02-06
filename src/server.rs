use std::net::SocketAddr;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::{http_client::HttpClient, server, RpcModule};
use tokio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = run_server().await?;

    let client = HttpClient::builder().build(format!("https://{}", addr))?;
    let response: String = client.request("test_method", rpc_params![]).await?;
    println!("[main]: http response: {:?}", response);

    Ok(())
}

async fn run_server() -> anyhow::Result<SocketAddr> {
    let server = server::Server::builder()
        .build("127.0.0.1:0".parse::<SocketAddr>()?)
        .await?;
    let mut module = RpcModule::new(());
    module
        .register_method("test_method", |_params, _, _| test_method())
        .unwrap();

    let addr = server.local_addr()?;
    let handle = server.start(module);

    tokio::spawn(handle.stopped());

    Ok(addr)
}

fn test_method() -> String {
    "testing!".to_string()
}
