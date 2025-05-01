pub mod service {
    use std::sync::Arc;

    use crate::protocol::proto::share_cert;
    use crate::protocol::proto::share_cert::*;
    use crate::protocol::server_state::ServerState;
    use tonic::{Request, Response, Status};

    use tonic::body::Body;

    #[derive(Debug)]
    pub struct ShareCertService {
        state: Arc<ServerState>,
    }

    impl ShareCertService {
        pub fn new(state: Arc<ServerState>) -> Self {
            Self { state }
        }

        pub fn server(state: Arc<ServerState>) -> cert_sharing_server::CertSharingServer<Self> {
            cert_sharing_server::CertSharingServer::new(Self::new(state))
        }
    }

    #[tonic::async_trait]
    impl cert_sharing_server::CertSharing for ShareCertService {
        async fn get_certificates(
            &self,
            request: tonic::Request<RequestCertificates>,
        ) -> std::result::Result<tonic::Response<ResponseCertificates>, tonic::Status> {
            self.state.key_store.read().await.list_certificates()
        }
    }
}
