use rustls::SignatureScheme;

pub fn supported_verif_algs() -> Vec<SignatureScheme> {
    rustls::crypto::CryptoProvider::get_default().unwrap().signature_verification_algorithms.supported_schemes()
}
