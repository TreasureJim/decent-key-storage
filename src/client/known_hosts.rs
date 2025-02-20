use base64::Engine;
use std::{collections::HashMap, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KnownHostsError {
    #[error("Encryption scheme was missing in the line during parsing")]
    ParsingMissingEncryptionScheme,
    #[error("Public key was missing in the line during parsing")]
    ParsingMissingPublicKey,
    #[error("Decoding public key")]
    DecodingPublicKey,
}

#[derive(Debug)]
pub struct KnownHosts {
    hosts: HashMap<String, Host>,
}

#[derive(Debug)]
pub struct Host {
    pub encryption_scheme: String,
    pub public_key: Vec<u8>,
}

impl KnownHosts {
    pub fn empty_hosts() -> Self {
        Self {
            hosts: HashMap::new(),
        }
    }

    pub fn deserialise_known_hosts(s: String) -> Result<KnownHosts, KnownHostsError> {
        let mut known_hosts = KnownHosts::empty_hosts();

        for line in s.lines() {
            let mut words = line.split_whitespace();

            let Some(host_name) = words.next() else {
                continue;
            };

            let host = Host {
            encryption_scheme: words
                .next()
                .ok_or(KnownHostsError::ParsingMissingEncryptionScheme)?.to_string(),
            public_key: base64::engine::general_purpose::STANDARD
                .decode(
                    words
                        .next()
                        .ok_or(KnownHostsError::ParsingMissingPublicKey)?,
                )
                .map_err(|_| KnownHostsError::DecodingPublicKey)?
            };

            known_hosts.add_host(host_name.to_string(), host);
        }

        Ok(known_hosts)
    }

    pub fn serialise_known_hosts(&self) -> String {
        let mut file_string = String::new();

        for (host_name, Host {encryption_scheme, public_key }) in &self.hosts {
            file_string.push_str(&format!("{} {} {}\n", host_name, encryption_scheme, base64::engine::general_purpose::STANDARD.encode(public_key)));
        }

        file_string
    }
}

impl KnownHosts {
    pub fn add_host(&mut self, host_name: String, host: Host) {
        self.hosts.insert(host_name, host); }

    pub fn get_host_key(&self, host_name: String) -> Option<&Host> {
        self.hosts.get(&host_name)
    }
}

static DEFAULT_LOCATION: &str = "~/.config/decent-key-storage/known_hosts";

/// Finds the default location of the known_hosts. If it doesn't exist, it creates it.
pub fn default_known_hosts_file() -> Result<&'static Path, std::io::Error> {
    let path = Path::new(DEFAULT_LOCATION);

    let exists = std::fs::exists(path)?;
    if !exists {
        std::fs::create_dir_all(path.parent().expect("Default location should always be able to get the parent directory."));
        std::fs::OpenOptions::new().write(true).create(true).open(path)?;
    }
    
    Ok(path)
}
