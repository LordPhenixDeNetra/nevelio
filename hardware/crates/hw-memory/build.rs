fn main() {
    // Déclarer le cfg custom pour éviter unexpected_cfg warnings
    println!("cargo::rustc-check-cfg=cfg(has_rowhammer)");

    // Compiler rowhammer.c seulement sur Linux x86_64
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_rowhammer();
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn compile_rowhammer() {
    let c_src = std::path::Path::new("../../../c/userspace/rowhammer.c");

    if !c_src.exists() {
        eprintln!(
            "cargo:warning=rowhammer.c introuvable à {:?} — module rowhammer désactivé",
            c_src
        );
        return;
    }

    let build_ok = cc::Build::new()
        .file(c_src)
        .flag("-O2")
        .flag_if_supported("-march=native")
        .flag("-Wall")
        // NE PAS définir ROWHAMMER_STANDALONE : on veut la lib, pas le main()
        .try_compile("nevelio_rowhammer")
        .is_ok();

    if build_ok {
        println!("cargo:rustc-cfg=has_rowhammer");
        println!("cargo:rerun-if-changed=../../../c/userspace/rowhammer.c");
    } else {
        eprintln!("cargo:warning=Compilation rowhammer.c échouée — test désactivé (gcc requis)");
    }
}
