use std::pin::Pin;
use std::sync::Once;
use std::task::{Context, Poll};

use http::Uri;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{
    connect::HttpConnector, Client as HyperClient, Error as HyperClientError,
};
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tonic::body::BoxBody;
use tower_service::Service;

// Inspired by https://github.com/LucioFranco/tonic-openssl/blob/master/example/src/client2.rs.

/// A communication channel which may either communicate using HTTP or HTTP over TLS. This
/// `Channel` can be passed directly to Tonic clients as a connector.
///
/// `Channel` implements the `Service` expected by Tonic for the underlying communication channel.
/// This strategy is necessary because Tonic removed the ability to pass in a raw `rustls`
/// configuration, and so Pants must implement its own connection setup logic to be able to
/// continue to use `rustls` directly.
#[derive(Clone, Debug)]
pub struct Channel {
    client: HyperClient<HttpsConnector<HttpConnector>, BoxBody>,
    uri: Uri,
}

impl Channel {
    pub async fn new(
        tls_config: &ClientConfig,
        uri: Uri,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let tls_config = tls_config.to_owned();

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http2()
            .build();

        let client = HyperClient::builder(TokioExecutor::new())
            .http2_only(true)
            .build(https);

        Ok(Self { client, uri })
    }
}

impl Service<http::Request<BoxBody>> for Channel {
    type Response = http::Response<Incoming>;
    type Error = HyperClientError;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: http::Request<BoxBody>) -> Self::Future {
        // Apparently the schema and authority do not get set by Hyper. Thus, the examples generally
        // copy the URI and replace the scheme and authority with the ones from the initial URI used
        // to configure the client.
        //
        // See https://github.com/LucioFranco/tonic-openssl/blob/bdaaecda437949244a1b4d61cb39110c4bcad019/example/src/client2.rs#L92
        // from the inspiration example
        let uri = Uri::builder()
            .scheme(self.uri.scheme().unwrap().clone())
            .authority(self.uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();
        *req.uri_mut() = uri;

        let client = self.client.clone();
        Box::pin(async move { client.request(req).await })
    }
}
