use std::sync::{Arc, Mutex};

use rustls::client::danger::ServerCertVerifier;

use crate::known_hosts::KnownHosts;

/// Initialize process-wide libraries needed for gRPC including the cryptography library used for rustls.
pub fn initialize() -> Result<(), String> {
    static mut INIT: bool = false;

    unsafe {
        if !INIT {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .map_err(|_| {
                    "Failed to initialize cryptography library needed for gRPC operations"
                })?;
            INIT = true;
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct CertTlsCapturer {
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertTlsCapturer {
    pub fn new() -> Self {
        Self {
            captured_cert: Arc::new(Mutex::new(None)),
        }
    }
}

impl ServerCertVerifier for CertTlsCapturer {
    fn verify_server_cert(
        &self,
        _end_entity: &tonic::transport::CertificateDer<'_>,
        _intermediates: &[tonic::transport::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut m = self.captured_cert.lock().unwrap();
        *m = Some(_end_entity.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tonic::transport::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tonic::transport::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crate::global::SUPPORTED_SCHEMES.to_vec()
    }
}

#[derive(Debug)]
pub struct KnownHostsTls<'a> {
    known_hosts: &'a KnownHosts
}

impl<'a> KnownHostsTls<'a> {
    pub fn new(known_hosts: &'a KnownHosts) -> Self {
        Self {
            known_hosts
        }
    }
}

impl<'a> ServerCertVerifier for KnownHostsTls<'a> {
    fn verify_server_cert(
        &self,
        _end_entity: &tonic::transport::CertificateDer<'_>,
        _intermediates: &[tonic::transport::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tonic::transport::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, rustls::crypto::WebPkiSupportedAlgorithms::).cipher_suites)
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tonic::transport::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crate::global::SUPPORTED_SCHEMES.to_vec()
    }
}
