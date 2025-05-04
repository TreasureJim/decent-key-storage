fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().type_attribute(".", "#[derive(Eq, Hash)]").compile_protos(&["proto/info.proto", "proto/public/share_cert.proto"], &["proto", "proto/public", "proto/private"])?;
    Ok(())
}
