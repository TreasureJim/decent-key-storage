use once_cell::sync::Lazy;
use rustls::client::danger::ServerCertVerifier;
use rustls::SignatureScheme;
use std::{collections::HashSet, sync::{
    mpsc::{Receiver, Sender},
    Arc,
}};
use thiserror::Error;
use tokio::sync::RwLock;
use x509_parser::{oid_registry, prelude::FromDer};

use crate::{
    key_storage::KeyStorage,
    keys::{CertificateData, HasKey},
};

pub type CaptureErrors = x509_parser::prelude::X509Error;

static OID_REGISTRY: Lazy<oid_registry::OidRegistry> =
    Lazy::new(|| oid_registry::OidRegistry::default().with_x509());

pub fn supported_verif_algs() -> Vec<SignatureScheme> {
    rustls::crypto::CryptoProvider::get_default()
        .unwrap()
        .signature_verification_algorithms
        .supported_schemes()
}

/// DANGEROUS - always allows the certificate, performs no checking. Uses the tokio sender to send the received certificate once it has been received.
#[derive(Debug)]
pub struct CertTlsCapturer {
    cert_transmitter: Sender<Result<CertificateData, CaptureErrors>>,
}

impl CertTlsCapturer {
    pub fn new() -> (Self, Receiver<Result<CertificateData, CaptureErrors>>) {
        let (tx, rx) = std::sync::mpsc::channel();

        (
            Self {
                cert_transmitter: tx,
            },
            rx,
        )
    }

    fn capture_cert(&self, cert: &tonic::transport::CertificateDer<'_>) {
        self.cert_transmitter
            .send(CertificateData::new(cert))
            .unwrap();
    }
}

impl ServerCertVerifier for CertTlsCapturer {
    fn verify_server_cert(
        &self,
        end_entity: &tonic::transport::CertificateDer<'_>,
        _intermediates: &[tonic::transport::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.capture_cert(end_entity);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_verif_algs()
    }
}

impl HasKey for HashSet<CertificateData> { 
    fn have_tonic_certificate(&self, cert: &tonic::transport::CertificateDer<'_>) -> bool {
        self.contains(&CertificateData::new_no_validation(cert))
    }
}


/// Uses the key store to check that the received certificate matches one in the key store
#[derive(Debug)]
pub struct CustomCertificateVerifier {
    key_store: Arc<dyn HasKey>,
}

impl CustomCertificateVerifier {
    pub fn new(key_store: Arc<dyn HasKey>) -> Self {
        Self { key_store }
    }
}

impl ServerCertVerifier for CustomCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &tonic::transport::CertificateDer<'_>,
        _intermediates: &[tonic::transport::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.key_store.have_tonic_certificate(end_entity) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InconsistentKeys(
                rustls::InconsistentKeys::KeyMismatch,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_verif_algs()
    }
}

/// DANGEROUS as name implies. Always returns the certificate as valid and correct, performs no
/// checking.
#[derive(Debug)]
pub struct DangerousCertificateVerifier {}

impl DangerousCertificateVerifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl ServerCertVerifier for DangerousCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &tonic::transport::CertificateDer<'_>,
        _intermediates: &[tonic::transport::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        supported_verif_algs()
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;

    use super::*;
    use crate::test_setup::INIT_CRYPTO;

    #[test]
    fn supported_algorithms_not_empty() {
        Lazy::force(&INIT_CRYPTO);

        assert!(!supported_verif_algs().is_empty())
    }
}
