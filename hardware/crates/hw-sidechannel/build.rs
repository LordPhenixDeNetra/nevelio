// build.rs — hw-sidechannel
//
// Sur Linux :
//   1. Cherche clang dans PATH
//   2. Compile chaque .bpf.c → OUT_DIR/*.bpf.o
//   3. Génère OUT_DIR/ebpf_programs.rs contenant include_bytes! des .o
//   4. Émet cargo:rustc-cfg=has_ebpf si tout réussit

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const EBPF_PROGRAMS: &[&str] = &["syscall_latency", "memory_access"];

fn main() {
    // Déclarer le cfg custom pour éviter les avertissements unexpected_cfg
    println!("cargo::rustc-check-cfg=cfg(has_ebpf)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // eBPF est Linux-only
    if target_os != "linux" {
        return;
    }

    // Seulement si la feature "ebpf" est activée
    let features = env::var("CARGO_FEATURE_EBPF");
    if features.is_err() {
        return;
    }

    compile_ebpf_programs();
}

fn compile_ebpf_programs() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest_dir.join("../../ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Vérifier que clang est disponible
    let clang_available = Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !clang_available {
        println!("cargo:warning=⚠ clang introuvable — programmes eBPF non compilés.");
        println!("cargo:warning=  sudo apt-get install clang llvm libbpf-dev");
        return;
    }

    // Détecter l'architecture cible pour les includes
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let arch_define = match target_arch.as_str() {
        "x86_64"  => "-D__TARGET_ARCH_x86_64",
        "aarch64" => "-D__TARGET_ARCH_arm64",
        other     => {
            println!("cargo:warning=Architecture {} non testée pour eBPF", other);
            "-D__TARGET_ARCH_x86_64"
        }
    };

    // Inclure les headers système BPF
    let include_paths: Vec<String> = vec![
        "-I/usr/include".into(),
        "-I/usr/include/x86_64-linux-gnu".into(),
    ];

    let mut all_compiled = Vec::new();

    for prog in EBPF_PROGRAMS {
        let src = ebpf_dir.join(format!("{}.bpf.c", prog));
        let dst = out_dir.join(format!("{}.bpf.o", prog));

        if !src.exists() {
            println!("cargo:warning=Source eBPF introuvable : {}", src.display());
            continue;
        }

        println!("cargo:rerun-if-changed={}", src.display());

        let mut args = vec![
            "-O2".to_string(),
            "-g".to_string(),
            "-target".to_string(), "bpf".to_string(),
            arch_define.to_string(),
        ];
        args.extend(include_paths.clone());
        args.extend([
            "-c".to_string(), src.to_str().unwrap().to_string(),
            "-o".to_string(), dst.to_str().unwrap().to_string(),
        ]);

        match Command::new("clang").args(&args).output() {
            Ok(output) if output.status.success() => {
                println!("cargo:warning=[eBPF] ✓ {} compilé", prog);
                all_compiled.push((*prog, dst));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("cargo:warning=[eBPF] ✗ Échec compilation {} :", prog);
                for line in stderr.lines().take(5) {
                    println!("cargo:warning=  {}", line);
                }
            }
            Err(e) => {
                println!("cargo:warning=[eBPF] Erreur clang : {}", e);
            }
        }
    }

    if all_compiled.is_empty() {
        println!("cargo:warning=[eBPF] Aucun programme compilé — checks eBPF désactivés.");
        return;
    }

    // Générer ebpf_programs.rs avec les include_bytes! de chaque .bpf.o
    let gen_path = out_dir.join("ebpf_programs.rs");
    let mut content = String::from(
        "// Généré par hw-sidechannel/build.rs — ne pas éditer\n\n"
    );

    for (name, obj_path) in &all_compiled {
        let const_name = name.to_uppercase().replace('-', "_");
        content.push_str(&format!(
            "pub(crate) const {}_BPF: &[u8] = include_bytes!({:?});\n",
            const_name,
            obj_path.to_str().unwrap(),
        ));
    }

    fs::write(&gen_path, &content).expect("Impossible d'écrire ebpf_programs.rs");

    // Signaler que les programmes eBPF sont disponibles
    println!("cargo:rustc-cfg=has_ebpf");
    println!("cargo:warning=[eBPF] {} programme(s) embarqué(s) dans le binaire.",
             all_compiled.len());
}
