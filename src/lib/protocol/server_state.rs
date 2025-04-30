use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{key_storage, protocol::info::ServerInfo};

#[derive(Debug)]
pub struct ServerState {
    pub info: ServerInfo,
    pub key_store: RwLock<key_storage::KeyStorage>
}

impl ServerState {
    pub fn new(info: ServerInfo, key_store: key_storage::KeyStorage) -> Arc<Self> {
        Arc::new(Self {
            info,
            key_store: RwLock::new(key_store)
        })
    }
}
