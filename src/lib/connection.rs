use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use rustls::RootCertStore;
use std::sync::Arc;
use thiserror::Error;

use http::Uri;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::TlsConnector;

use crate::{
    custom_tls::CaptureErrors,
    keys::{CertificateData, HasKey},
    HostPort,
};

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Failed to connect: {0:?}")]
    Connection(std::io::Error),
    #[error("Failed resolve hostname to a DNS name")]
    DNS,
    #[error("Certificate error: {0:?}")]
    Certificate(CaptureErrors),
}

impl From<std::io::Error> for ConnectionError {
    fn from(value: std::io::Error) -> Self {
        Self::Connection(value)
    }
}

pub async fn connect_and_get_cert(target: &HostPort) -> Result<CertificateData, ConnectionError> {
    let (cert_capturer, cert_listener) = crate::custom_tls::CertTlsCapturer::new();
    let unsafe_tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(cert_capturer))
        .with_no_client_auth();

    let tcp_stream = TcpStream::connect(&target.addr).await?;
    let mut stream = TlsConnector::from(Arc::new(unsafe_tls_config))
        .connect(
            target
                .addr
                .ip()
                .try_into()
                .map_err(|_| ConnectionError::DNS)?,
            tcp_stream,
        )
        .await?;

    // trigger handshake
    stream.write_all(&vec![]).await?;
    stream.flush().await?;

    let captured_cert = cert_listener
        .recv()
        .expect("Cert capturer dropped")
        .map_err(|err| ConnectionError::Certificate(err))?;

    Ok(captured_cert)
}

fn custom_cert_verif_client<B>(
    custom_cert_verif: Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, B>
where
    B: tonic::transport::Body + Send,
    B::Data: Send,
{
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(custom_cert_verif)
        .with_no_client_auth();

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let connector = tower::ServiceBuilder::new()
        .layer_fn(move |s| {
            let tls = tls.clone();

            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_or_http()
                .enable_http2()
                .wrap_connector(s)
        })
        .service(http);

    hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build::<_, B>(connector)
}

/// Uses the key store to check that the received certificate matches one in the key store.
pub fn safe_client<B>(
    key_store: Arc<dyn HasKey>,
) -> hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, B>
where
    B: tonic::transport::Body + Send,
    B::Data: Send,
{
    custom_cert_verif_client(Arc::new(crate::custom_tls::CustomCertificateVerifier::new(
        key_store,
    )))
}

/// DANGEROUS as name implies. Always returns the certificate as valid and correct, performs no checking.
pub fn dangerous_client<B>() -> hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, B>
where
    B: tonic::transport::Body + Send,
    B::Data: Send,
{
    custom_cert_verif_client(Arc::new(
        crate::custom_tls::DangerousCertificateVerifier::new(),
    ))
}

#[cfg(test)]
mod tests {
    use crate::test_setup::INIT_CRYPTO;

    use super::*;
    use once_cell::sync::Lazy;
    use rcgen::CertifiedKey;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{pki_types::pem::PemObject, ServerConfig};
    use std::mem;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::task;
    use tokio_rustls::TlsAcceptor;

    pub struct TestServer {
        pub port: u16,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl TestServer {
        pub async fn new(cert: &[u8], key: &[u8]) -> Self {
            // Bind to random available port
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            // Configure TLS
            let config =
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![CertificateDer::from_pem_slice(&cert)
                            .expect("Could not read certificate")],
                        PrivateKeyDer::from_pem_slice(&key).expect("Could not read key"),
                    )
                    .unwrap();

            let acceptor = TlsAcceptor::from(Arc::new(config));

            // Create shutdown channel
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

            tokio::spawn(async move {
                tokio::select! {
                    _ = async {
                        loop {
                            match listener.accept().await {
                                Ok((stream, _)) => {
                                    let acceptor = acceptor.clone();
                                    tokio::spawn(async move {
                                        if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                                            // Simple echo server
                                            let mut buf = [0; 1024];
                                            while let Ok(n) = tls_stream.read(&mut buf).await {
                                                if n == 0 {
                                                    break;
                                                }
                                                tls_stream.write_all(&buf[..n]).await.unwrap();
                                            }
                                        }
                                    });
                                }
                                Err(e) => eprintln!("Accept error: {}", e),
                            }
                        }
                    } => {},
                    _ = shutdown_rx => {},
                }
            });

            // Verify server is ready
            Self::verify_server_ready(port).await;

            TestServer {
                port,
                shutdown: Some(shutdown_tx),
            }
        }

        async fn verify_server_ready(port: u16) {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(5) {
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            panic!("Test server failed to start on port {}", port);
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let Some(shutdown) = self.shutdown.take() else {
                return;
            };
            let _ = shutdown.send(());
        }
    }

    #[tokio::test]
    async fn test_connect_and_get_cert_success() {
        Lazy::force(&INIT_CRYPTO);

        let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = cert.pem();
        let key = key_pair.serialize_pem();
        let test_cert = cert.as_ref();
        let test_key = key.as_ref();

        let (_, parsed_cert) =
            x509_parser::pem::parse_x509_pem(&test_cert).expect("Cert parse error");
        let parsed_cert = parsed_cert.parse_x509().unwrap();
        let public_key = parsed_cert.public_key();

        let server = TestServer::new(&test_cert, &test_key).await;

        // Test our function
        let target = format!("{}:{}", "localhost", server.port)
            .parse::<SocketAddr>()
            .unwrap()
            .into();

        let host = connect_and_get_cert(&target)
            .await
            .expect("Failed to get cert");
        assert_eq!(&*host, public_key.raw);
    }

    #[tokio::test]
    async fn test_connect_and_get_cert_connection_error() {
        Lazy::force(&INIT_CRYPTO);

        // Test with non-existent port
        let target = format!("{}:{}", "localhost", 9999)
            .parse::<SocketAddr>()
            .unwrap()
            .into();

        let result = connect_and_get_cert(&target).await;
        assert!(matches!(result, Err(ConnectionError::Connection(_))));
    }
}
