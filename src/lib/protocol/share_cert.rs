pub mod service {
    use std::sync::Arc;

    use crate::protocol::proto::share_cert;
    use crate::protocol::proto::share_cert::*;
    use crate::protocol::server_state::ServerState;
    use itertools::Itertools;
    use tonic::{Request, Response, Status};
    use uuid::Uuid;

    use crate::keys::CertWithMetadata;
    use tonic::body::Body;

    impl From<CertWithMetadata<'_>> for share_cert::response_certificates::Certificate {
        fn from(value: CertWithMetadata) -> Self {
            Self {
                uuid: value.metadata.uuid.to_string(),
                socket: value.metadata.sock_addr.to_string(),
                cert: value.cert.to_vec(),
            }
        }
    }

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
            let request = request.into_inner();

            if request.uuids.is_empty() {
                Ok(tonic::Response::new(share_cert::ResponseCertificates {
                    uuid: self.state.info.uuid.to_string(),
                    certificates: self
                        .state
                        .key_store
                        .read()
                        .await
                        .get_certificates()
                        .into_iter()
                        .map(|c| c.into())
                        .collect(),
                }))
            } else {
                let key_store = self.state.key_store.read().await;
                Ok(tonic::Response::new(share_cert::ResponseCertificates {
                    uuid: self.state.info.uuid.to_string(),
                    certificates: request
                        .uuids
                        .iter()
                        .map(|str| {
                            let uuid = str.parse::<Uuid>().map_err(|e| {
                                Status::invalid_argument(format!("Uuid must be valid: {e}"))
                            })?;
                            Ok(key_store
                                .get_certificate_uuid(&uuid)
                                .ok_or(Status::not_found(format!("Uuid {uuid} not found.")))?
                                .into())
                        })
                        .collect::<Result<Vec<_>, tonic::Status>>()?,
                }))
            }
        }
    }
}
