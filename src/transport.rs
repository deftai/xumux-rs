//! Socket settings for low latency.
use std::io;

use tokio::net::TcpStream;

/// Unsent bytes allowed in the kernel on a tuned socket.
pub const NOTSENT_LOWAT: u32 = 16 * 1024;

/// Turns off Nagle, and limits unsent data in the kernel.
///
/// Priority only reorders frames still in this process. Once frames are in the socket buffer nothing
/// can overtake them, and that buffer can hold megabytes, so a bulk channel would delay input by
/// however long it takes to drain. `TCP_NOTSENT_LOWAT` keeps them here, where the scheduler can see
/// them. Windows and other systems without the option get only `TCP_NODELAY`.
pub fn tune_tcp(sock: &TcpStream) -> io::Result<()> {
    sock.set_nodelay(true)?;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const TCP_NOTSENT_LOWAT: libc::c_int = 25;
        let value: libc::c_int = NOTSENT_LOWAT as libc::c_int;
        // SAFETY: the fd is valid for the call, and the pointer and length describe `value`.
        let r = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                (&raw const value).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
