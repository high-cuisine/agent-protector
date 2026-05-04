#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;
pub const FILENAME_LEN: usize = 256;

/// Event emitted by eBPF on every execve syscall.
/// `pid` is actually the TGID (what userspace calls PID).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
