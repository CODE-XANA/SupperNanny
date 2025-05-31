use std::{env, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_path = PathBuf::from("src/ebpf/kern/exec_intercept.c");

    let status = std::process::Command::new("clang")
        .args(&[
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include",
            "-I.",
            "-Wall",
            "-Werror",
            "-fno-stack-protector",
            "-fno-PIC",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-Wno-address-of-packed-member",
            "-Wno-tautological-compare",
            "-Wno-unknown-warning-option",
            "-Wno-unused-but-set-variable",
            "-Wno-gnu-variable-sized-type-not-at-end",
            "-Wno-incompatible-pointer-types",
            "-Wno-unused-function",
            "-Wno-missing-field-initializers",
            "-Wno-unused-variable",
            "-Wno-int-conversion",
            "-Wno-format",
            "-Wno-sign-compare",
            "-I/usr/include/linux",
            "-I./src/ebpf/kern/",
            "-I./src/ebpf/kern/include/",
            "-I./src/ebpf/kern/include/uapi",
            "-c",
            "src/ebpf/kern/exec_intercept.c",
            "-o",
            &format!("{}/exec_intercept.o", out_dir.display()),
        ])
        .status()
        .expect("failed to compile eBPF program");

    if !status.success() {
        panic!("BPF program compilation failed");
    }

    println!("cargo:rerun-if-changed=src/ebpf/kern/exec_intercept.c");
}
