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

