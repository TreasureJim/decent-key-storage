pub mod protocol {
    tonic::include_proto!("info");
}

pub mod service {
    use std::sync::Arc;

    use crate::protocol::server_state::ServerState;
    use super::protocol::server_info_server::ServerInfo;
    use tonic::{Request, Response, Status};

    use tonic::body::Body;

    #[derive(Debug)]
    pub struct InformationService {
        state: Arc<ServerState>,
    }

    impl InformationService {
        pub fn new(state: Arc<ServerState>) -> Self {
            Self { state }
        }
        
        pub fn server(state: Arc<ServerState>) -> super::protocol::server_info_server::ServerInfoServer<Self> {
            super::protocol::server_info_server::ServerInfoServer::new(Self::new(state))
        }
    }

    #[tonic::async_trait]
    impl ServerInfo for InformationService {
        async fn get_server_info(
            &self,
            request: Request<super::protocol::ServerInfoRequest>,
        ) -> Result<Response<super::protocol::ServerInfoResponse>, Status> {
            let reply = super::protocol::ServerInfoResponse {
                uuid: self.state.info.uuid.to_string(),
            };
            Ok(Response::new(reply))
        }
    }
}

use std::{path::{Path, PathBuf}, str::FromStr, sync::Arc};
use uuid::Uuid;
use anyhow::Context;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::fs;

pub const SERVER_INFO_FILE: &str = "info.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub uuid: uuid::Uuid,
}

impl From<protocol::ServerInfoResponse> for ServerInfo {
    fn from(value: protocol::ServerInfoResponse) -> Self {
        Self {
            uuid: Uuid::from_str(&value.uuid).expect("Invalid UUID")
        }
    }
}

#[derive(Debug, Error)]
pub enum ServerInfoError {
    #[error("Failed to read server info from {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse server info from {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to write server info to {path}: {source}")]
    WriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to create new server info at {path}: {source}")]
    CreateFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Verification failed for newly created server info at {path}")]
    VerificationFailed { path: PathBuf },
}

impl ServerInfo {
    /// Loads from file or creates new one if not found
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, ServerInfoError> {
        let path = path.as_ref();
        log::debug!("Attempting to load server info from {}", path.display());

        match Self::load(path) {
            Ok(info) => {
                log::info!("Successfully loaded server info from {}", path.display());
                Ok(info)
            }
            Err(ServerInfoError::ReadFailed { .. }) => {
                log::warn!("Server info not found at {}, creating new", path.display());
                let new_info = Self {
                    uuid: Uuid::new_v4(),
                };

                log::debug!("Generated new server info with UUID: {}", new_info.uuid);
                new_info.save(path)?;
                log::info!("Created new server info at {}", path.display());

                log::debug!("Verifying newly created server info");
                let loaded = Self::load(path)?;
                if loaded.uuid != new_info.uuid {
                    log::error!("Verification failed for server info at {}", path.display());
                    return Err(ServerInfoError::VerificationFailed {
                        path: path.to_path_buf(),
                    });
                }

                log::info!("Successfully verified new server info");
                Ok(loaded)
            }
            Err(e) => {
                log::error!("Failed to load server info: {}", e);
                Err(e)
            }
        }
    }

    /// Loads server info from file
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ServerInfoError> {
        let path = path.as_ref();
        log::debug!("Reading server info file at {}", path.display());

        let json = fs::read_to_string(path).map_err(|source| {
            log::debug!("Read operation failed for {}: {}", path.display(), source);
            ServerInfoError::ReadFailed {
                path: path.to_path_buf(),
                source,
            }
        })?;

        log::debug!("Parsing server info JSON");
        serde_json::from_str(&json).map_err(|source| {
            log::error!("Failed to parse JSON from {}: {}", path.display(), source);
            ServerInfoError::ParseFailed {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    /// Saves server info to file
pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ServerInfoError> {
    let path = path.as_ref();
    log::debug!("Saving server info to {}", path.display());

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| {
            log::error!("Directory creation failed: {}", source);
            ServerInfoError::WriteFailed {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }

    let json = serde_json::to_string_pretty(self).unwrap();
    
    fs::write(path, json).map_err(|source| {
        ServerInfoError::WriteFailed {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Serializes ServerInfo to JSON file
pub fn save_server_info(info: &ServerInfo, path: impl AsRef<Path>) -> anyhow::Result<()> {
    let json =
        serde_json::to_string_pretty(info).context("Failed to serialize server info to JSON")?;

    std::fs::write(&path, json)
        .with_context(|| format!("Failed to write server info to {}", path.as_ref().display()))?;

    Ok(())
}

/// Deserializes ServerInfo from JSON file
pub fn load_server_info(path: impl AsRef<Path>) -> anyhow::Result<ServerInfo> {
    let json = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to read server info from {}",
            path.as_ref().display()
        )
    })?;

    serde_json::from_str(&json).with_context(|| {
        format!(
            "Failed to parse server info from {}",
            path.as_ref().display()
        )
    })
}
}
