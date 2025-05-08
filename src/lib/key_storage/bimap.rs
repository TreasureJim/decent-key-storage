use std::{collections::HashMap, sync::Arc};

use uuid::Uuid;

use crate::keys::CertificateData;

#[derive(Debug)]
pub struct UuidCertBiMap {
    uuid_to_cert: HashMap<Uuid, Arc<CertificateData>>,
    cert_to_uuid: HashMap<Arc<CertificateData>, Uuid>,
}

impl UuidCertBiMap {
    pub fn new() -> Self {
        Self {
            uuid_to_cert: HashMap::new(),
            cert_to_uuid: HashMap::new(),
        }
    }

    pub fn get_cert(&self, uuid: &Uuid) -> Option<&Arc<CertificateData>> {
        self.uuid_to_cert.get(uuid)
    }

    pub fn get_uuid(&self, cert: &CertificateData) -> Option<&Uuid> {
        self.cert_to_uuid.get(cert)
    }

    /// Returns true if map already contained certicate
    pub fn insert(&mut self, uuid: Uuid, cert: CertificateData)  {
        let rc = Arc::new(cert);
        self.uuid_to_cert.insert(uuid, rc.clone());
        self.cert_to_uuid.insert(rc, uuid);
    }

    pub fn get_all_certificates(&self) -> Vec<&Arc<CertificateData>> {
        self.cert_to_uuid.keys().collect()
    }

    pub fn get_all_uuids(&self) -> Vec<&Uuid> {
        self.uuid_to_cert.keys().collect()
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, Uuid, Arc<CertificateData>> {
        self.uuid_to_cert.iter()
    }
}
