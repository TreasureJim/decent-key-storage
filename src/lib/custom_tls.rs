use once_cell::sync::Lazy;
use rustls::client::danger::ServerCertVerifier;
use rustls::SignatureScheme;
use std::sync::mpsc::{Receiver, Sender};
use x509_parser::{oid_registry, prelude::FromDer};
use thiserror::Error;

use crate::{key_storage::Certificate, keys::Key};

static OID_REGISTRY: Lazy<oid_registry::OidRegistry> = Lazy::new(|| {
        oid_registry::OidRegistry::default().with_x509()
});

#[derive(Error, Debug)]
pub enum CaptureErrors {
    #[error("x509 certificate parsing failed")]
    Parsing,
    #[error("Could not identify the algorithm with Oid {oid:?})")]
    UnidentifiedAlgorithm {
        oid: String
    }
}

pub fn supported_verif_algs() -> Vec<SignatureScheme> {
    rustls::crypto::CryptoProvider::get_default().unwrap().signature_verification_algorithms.supported_schemes()
}

#[derive(Debug)]
pub struct CertTlsCapturer {
    cert_transmitter: Sender<Result<Certificate, CaptureErrors>>,
}

impl CertTlsCapturer {
    pub fn new() -> (Self, Receiver<Result<Certificate, CaptureErrors>>) {
        let (tx, rx) = std::sync::mpsc::channel();

        (
            Self {
                cert_transmitter: tx,
            },
            rx,
        )
    }

    fn capture_cert(&self, data: &[u8]) {
        let Ok((_, cert)) = x509_parser::prelude::X509Certificate::from_der(data) else {
            self.cert_transmitter.send(Err(CaptureErrors::Parsing)).unwrap();
            return;
        };
    
        let Ok(alg) = x509_parser::prelude::oid2sn(&cert.signature.algorithm, &OID_REGISTRY) else {
            self.cert_transmitter.send(Err(CaptureErrors::UnidentifiedAlgorithm { oid: cert.signature.algorithm.to_id_string() })).unwrap();
            return;
        };

        self.cert_transmitter.send(Ok(
            Certificate {
                encryption_scheme: alg.to_string(),
                public_key: cert.public_key().raw.to_vec()
            }
        )).unwrap();
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
        self.capture_cert(&end_entity.to_vec());
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
