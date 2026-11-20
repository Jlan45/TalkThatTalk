use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist_dir = manifest_dir.join("../../web/dist");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = out_dir.join("embedded_web.rs");

    println!("cargo:rerun-if-changed={}", dist_dir.display());

    let mut entries = Vec::new();
    if dist_dir.is_dir() {
        collect_files(&dist_dir, &dist_dir, &mut entries);
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut code = String::from("pub fn get_asset(path: &str) -> Option<(&'static [u8], &'static str)> {\n    match path {\n");
    for (rel_path, abs_path) in &entries {
        println!("cargo:rerun-if-changed={}", abs_path.display());
        let mime = guess_mime(rel_path);
        let abs_str = abs_path.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
        code.push_str(&format!(
            "        \"{rel_path}\" => Some((include_bytes!(\"{abs_str}\"), \"{mime}\")),\n"
        ));
    }
    code.push_str("        _ => None,\n    }\n}\n");

    fs::write(&out_file, code).expect("failed to write embedded_web.rs");
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else if path.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            let rel_unix = rel.to_string_lossy().replace('\\', "/");
            if let Ok(canon) = path.canonicalize() {
                out.push((rel_unix, canon));
            }
        }
    }
}

fn guess_mime(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") || path.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}
