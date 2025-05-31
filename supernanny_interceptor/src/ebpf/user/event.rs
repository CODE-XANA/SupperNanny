// src/ebpf/user/event.rs

use aya::Pod;

pub const MAX_ARGS: usize = 8;
pub const ARG_LEN: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub argc: u32,
    pub argv: [[u8; ARG_LEN]; MAX_ARGS],
}

unsafe impl Pod for ExecEvent {}

#[allow(dead_code)]
pub fn print_event_size() {
    println!("🎯 Rust ExecEvent size: {}", std::mem::size_of::<ExecEvent>());
}
