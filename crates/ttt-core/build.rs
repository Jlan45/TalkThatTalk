use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

fn main() {
    let workspace = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let source = workspace.join("target/antigravity-oauth");
    println!("cargo:rerun-if-changed={}", source.display());
    let credentials = match fs::read_to_string(source) {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => panic!("failed to read prepared Antigravity OAuth defaults: {err}"),
    };
    let (id, secret) = if let Some(credentials) = credentials.as_deref() {
        let mut lines = credentials.lines();
        let id = lines.next().filter(|id| !id.is_empty());
        let secret = lines.next().filter(|secret| !secret.is_empty());
        assert!(
            id.is_some() && secret.is_some() && lines.next().is_none(),
            "invalid Antigravity OAuth defaults, rerun scripts/prepare-antigravity-oauth.mjs"
        );
        (id, secret)
    } else {
        (None, None)
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("antigravity_oauth.rs");
    fs::write(
        output,
        format!(
            "const ANTIGRAVITY_DESKTOP_CLIENT_ID: Option<&str> = {id:?};\n\
             const ANTIGRAVITY_DESKTOP_CLIENT_SECRET: Option<&str> = {secret:?};\n"
        ),
    )
    .expect("write Antigravity OAuth defaults");
}
