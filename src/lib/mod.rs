#![allow(dead_code, unused_imports, unused_variables)]

use std::net::SocketAddr;

use anyhow::Context;
use bytes::Bytes;

use tokio::net::ToSocketAddrs;
pub mod connection;
pub mod custom_tls;
pub mod key_storage;
pub mod keys;
pub mod protocol;
pub mod tls;

#[derive(Clone, Copy, Debug)]
pub struct HostPort {
    pub addr: SocketAddr
}

impl HostPort {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr
        }
    }

    pub fn to_endpoint(&self) -> anyhow::Result<tonic::transport::Endpoint> {
        tonic::transport::Endpoint::from_shared(self).context(format!("Failed to convert {} to a tonic endpoint", self.addr))
    }

    pub fn parse_arg(arg: &str) -> anyhow::Result<Self> {
        Ok(arg.parse::<SocketAddr>()?.into())
    }
}

impl Into<Bytes> for &HostPort {
    fn into(self) -> Bytes {
        format!("https://{}", self.addr).into()
    }
}

impl Into<http::Uri> for &HostPort {
    fn into(self) -> http::Uri {
        http::Uri::builder().scheme("https").authority(self.to_string()).path_and_query("/").build().unwrap()
    }
}

impl From<SocketAddr> for HostPort {
    fn from(value: SocketAddr) -> Self {
        HostPort::new(value)
    }
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
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
