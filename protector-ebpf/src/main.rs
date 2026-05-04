#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use protector_common::{ExecEvent, COMM_LEN, FILENAME_LEN};

// 256 KB ring buffer shared across all CPUs
#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn protector(ctx: TracePointContext) -> u32 {
    match try_protector(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_protector(ctx: TracePointContext) -> Result<u32, i64> {
    // sys_enter_execve tracepoint layout (64-bit kernel):
    //   [0..8]  common header (type u16, flags u8, preempt u8, pid s32)
    //   [8..16] __syscall_nr (s32) + 4-byte pad for pointer alignment
    //   [16]    const char __user *filename
    //   [24]    const char __user * const __user *argv
    let filename_ptr: u64 = unsafe { ctx.read_at(16) }.map_err(|e| e as i64)?;

    // Upper 32 bits = TGID (what userspace knows as the PID).
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;

    let mut event = ExecEvent {
        pid: tgid,
        uid,
        comm: [0u8; COMM_LEN],
        filename: [0u8; FILENAME_LEN],
    };

    unsafe { bpf_get_current_comm(&mut event.comm) }.map_err(|e| e as i64)?;
    unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename) }
        .map_err(|e| e as i64)?;

    // output() does a single copy into the ring buffer — no reserve/submit needed
    RING_BUF.output(&event, 0).ok();

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
