#![allow(dead_code, unused_imports, unused_variables)]

use anyhow::Context;
use bytes::Bytes;

use tokio::net::ToSocketAddrs;
pub mod connection;
pub mod custom_tls;
pub mod key_storage;
pub mod keys;
pub mod protocol;
pub mod tls;

pub type HostPort = std::net::SocketAddr;

pub fn to_endpoint(addr: &std::net::SocketAddr) -> anyhow::Result<tonic::transport::Endpoint> {
    tonic::transport::Endpoint::from_shared(format!("https://{}", addr)).context(format!("Failed to convert {} to a tonic endpoint", addr))
}

/* impl TryInto<tonic::transport::Endpoint> for &HostPort {
    type Error = tonic::transport::Error;

    fn try_into(self) -> Result<tonic::transport::Endpoint, Self::Error> {
        tonic::transport::Endpoint::from_shared(format!("https://{}:{}", self.ip(), self.port()).to_string())
    }
} */

/* #[derive(Clone, Debug)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl Into<Bytes> for &HostPort {
    fn into(self) -> Bytes {
        format!("{}:{}", self.host, self.port).into()
    }
}

impl TryInto<tonic::transport::Endpoint> for &HostPort {
    type Error = tonic::transport::Error;

    fn try_into(self) -> Result<tonic::transport::Endpoint, Self::Error> {
        tonic::transport::Endpoint::from_shared(format!("https://{}:{}", self.host, self.port).to_string())
    }
}
*/

#[cfg(test)]
mod test_setup {
    use once_cell::sync::Lazy;

    pub static INIT_CRYPTO: Lazy<()> = Lazy::new(|| {
        crate::tls::initialize().expect("Failed to initialise crypto");
    });
} 
