fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("cargo:rerun-if-changed=src/WhisperTextProtocol.proto");

  let mut config = prost_build::Config::new();
  config.out_dir("src/");

  config.compile_protos(&["src/WhisperTextProtocol.proto"], &["src/"])?;
  config.compile_protos(&["src/groups.proto"], &["src/"])?;

  Ok(())
}
