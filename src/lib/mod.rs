#![allow(dead_code, unused_imports, unused_variables)]

use tokio::net::ToSocketAddrs;
pub mod channel;
pub mod connection;
pub mod custom_tls;
pub mod key_storage;
pub mod keys;
pub mod tls;

#[derive(Clone, Debug)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

#[cfg(test)]
mod test_setup {
    use once_cell::sync::Lazy;

    pub static INIT_CRYPTO: Lazy<()> = Lazy::new(|| {
        crate::tls::initialize().expect("Failed to initialise crypto");
    });
}
