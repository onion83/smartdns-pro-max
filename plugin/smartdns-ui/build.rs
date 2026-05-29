use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

fn get_git_commit_version() {
    let result = std::process::Command::new("git")
        .args(&["describe", "--tags", "--always", "--dirty"])
        .output();

    let git_version = match result {
        Ok(output) => output.stdout,
        Err(_) => Vec::new(),
    };

    let git_version = String::from_utf8(git_version).expect("Invalid UTF-8 sequence");
    println!("cargo:rustc-env=GIT_VERSION={}", git_version.trim());
}

fn link_rename_lib() {
    let release_plugin = env::var("RELEASE_PLUGIN").is_ok();

    if release_plugin == false {
        return;
    }

    let curr_source_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir =
        env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| format!("{}/target", curr_source_dir));
    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap().replace("-", "_");
    let so_path = format!("{}/{}.so", target_dir, crate_name);
    println!("cargo:rustc-link-arg=-o");
    println!("cargo:rustc-link-arg={}", so_path);
}

/// 用 bindgen 库生成 bindings（glibc 系统）
fn gen_bindings_with_lib(
    smartdns_inc_dir: &str,
    smartdns_src_dir: &str,
    out_path: &PathBuf,
    sysroot: &Option<String>,
) {
    let ignored_macros = IgnoreMacros(vec!["IPPORT_RESERVED".into()].into_iter().collect());

    let mut bindings_builder =
        bindgen::Builder::default().header(format!("{}/smartdns/smartdns.h", smartdns_inc_dir));
    if let Some(sysroot) = sysroot {
        bindings_builder = bindings_builder.clang_arg(format!("--sysroot={}", sysroot));
    }
    let bindings = bindings_builder
        .clang_arg(format!("-I{}", smartdns_src_dir))
        .parse_callbacks(Box::new(ignored_macros))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("smartdns_bindings.rs"))
        .expect("Couldn't write bindings!");
}

/// 用 bindgen-cli 生成 bindings（Alpine/musl 系统，libloading 无法 dlopen libclang.so）
fn gen_bindings_with_cli(
    smartdns_inc_dir: &str,
    smartdns_src_dir: &str,
    out_path: &PathBuf,
) {
    let ignored_macros = IgnoreMacros(vec!["IPPORT_RESERVED".into()].into_iter().collect());

    // 生成主 bindings
    let output = Command::new("bindgen")
        .args(&[
            &format!("{}/smartdns/smartdns.h", smartdns_inc_dir),
            "--use-core",
            "--with-derive-default",
            "--with-derive-partialeq",
            "--with-derive-eq",
            "--with-derive-hash",
            "--impl-debug",
            "--blocklist-item", "IPPORT_RESERVED",
            "--",
            "-I", &smartdns_inc_dir,
            "-I", &smartdns_src_dir,
        ])
        .args(&["-o", &out_path.join("smartdns_bindings.rs").to_string_lossy()])
        .output()
        .expect("Failed to execute bindgen-cli");

    if !output.status.success() {
        panic!(
            "bindgen-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn link_smartdns_lib() {
    let curr_source_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let smartdns_src_dir = format!("{}/../../src", curr_source_dir);
    let smartdns_inc_dir = format!("{}/include", smartdns_src_dir);
    let smartdns_lib_file = format!("{}/libsmartdns-test.a", smartdns_src_dir);

    let cc = env::var("RUSTC_LINKER")
        .unwrap_or_else(|_| env::var("CC").unwrap_or_else(|_| "cc".to_string()));

    let sysroot_output = std::process::Command::new(&cc)
        .arg("--print-sysroot")
        .output();
    let mut sysroot = None;
    if let Ok(output) = sysroot_output {
        if output.status.success() {
            let path = String::from_utf8(output.stdout).unwrap();
            sysroot = Some(path.trim().to_string());
        }
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // 检测是否是 musl 目标（Alpine），用 bindgen-cli 替代 bindgen 库
    let target = env::var("TARGET").unwrap_or_default();
    let is_musl = target.contains("musl");

    if is_musl {
        gen_bindings_with_cli(&smartdns_inc_dir, &smartdns_src_dir, &out_path);
    } else {
        gen_bindings_with_lib(
            &smartdns_inc_dir,
            &smartdns_src_dir,
            &out_path,
            &sysroot,
        );
    }

    // Generate additional bindings for geosite functions
    let geosite_bindings = bindgen::Builder::default()
        .header(format!("{}/dns_conf/geosite.h", smartdns_src_dir))
        .clang_arg(format!("-I{}", smartdns_src_dir))
        .allowlist_function("geosite_resolve_dat_path")
        .allowlist_function("geosite_get_updater_config")
        .allowlist_function("geosite_download_url_files_sync")
        .allowlist_function("geosite_download_url_files_sync_force")
        .allowlist_function("geosite_download_single_url_file_sync")
        .allowlist_function("geosite_dat_list_to_json")
        .allowlist_type("geosite_updater_config")
        .generate()
        .expect("Unable to generate geosite bindings");
    geosite_bindings
        .write_to_file(out_path.join("geosite_bindings.rs"))
        .expect("Couldn't write geosite bindings!");

    if std::path::Path::new(&smartdns_lib_file).exists() && !cfg!(feature = "build-release") {
        println!("cargo:rerun-if-changed={}", smartdns_lib_file);
        println!("cargo:rustc-link-lib=static=smartdns-test");
        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-search=native={}", smartdns_src_dir);
    }
}

fn main() {
    get_git_commit_version();
    link_smartdns_lib();
    link_rename_lib();
}
