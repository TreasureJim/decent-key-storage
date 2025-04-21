use std::sync::Arc;
use crate::protocol::info::ServerInfo;

#[derive(Debug)]
pub struct ServerState {
    pub info: ServerInfo
}

impl ServerState {
    pub fn new(info: ServerInfo) -> Arc<Self> {
        Arc::new(Self {
            info
        })
    }
}
