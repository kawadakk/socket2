// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;
use std::marker::PhantomData;
use std::mem::{self, size_of, MaybeUninit};
use std::net::Shutdown;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "all")]
use std::num::NonZeroUsize;
#[cfg(feature = "all")]
use std::os::solid::ffi::OsStrExt;
#[cfg(feature = "all")]
use std::os::solid::io::RawFd;
use std::os::solid::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::time::{Duration, Instant};
use std::{io, slice};

use abi::{in6_addr, in_addr};
use libc::{c_void, ssize_t};

use crate::{Domain, Protocol, SockAddr, TcpKeepalive, Type};

pub(crate) use libc::c_int;

#[path = "solid/abi.rs"]
mod abi;

// Used in `Domain`.
pub(crate) use abi::{AF_INET, AF_INET6};
// Used in `Type`.
#[cfg(feature = "all")]
pub(crate) use abi::SOCK_RAW;
#[cfg(feature = "all")]
pub(crate) use abi::SOCK_SEQPACKET;
pub(crate) use abi::{SOCK_DGRAM, SOCK_STREAM};
// Used in `Protocol`.
pub(crate) use abi::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
// Used in `SockAddr`.
pub(crate) use abi::{
    sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t,
};
// Used in `Socket`.
pub(crate) use abi::IP_TOS;
pub(crate) use abi::SO_LINGER;
pub(crate) use abi::{
    ip_mreq as IpMreq, ipv6_mreq as Ipv6Mreq, linger, IPPROTO_IP, IPPROTO_IPV6,
    IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF, IPV6_MULTICAST_LOOP, IPV6_UNICAST_HOPS, IPV6_V6ONLY,
    IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, IP_MULTICAST_IF, IP_MULTICAST_LOOP, IP_MULTICAST_TTL,
    IP_TTL, MSG_OOB, MSG_PEEK, SOL_SOCKET, SO_BROADCAST, SO_ERROR, SO_KEEPALIVE, SO_RCVBUF,
    SO_RCVTIMEO, SO_REUSEADDR, SO_SNDBUF, SO_SNDTIMEO, SO_TYPE, TCP_NODELAY,
};
pub(crate) use abi::{IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP};

#[cfg(all(feature = "all"))]
pub(crate) use abi::{TCP_KEEPCNT, TCP_KEEPINTVL};

// See this type in the Windows file.
pub(crate) type Bool = c_int;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { abi::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

/// Maximum size of a buffer passed to system call like `recv` and `send`.
const MAX_BUF_LEN: usize = <ssize_t>::max_value() as usize;

impl_debug!(
    Domain,
    abi::AF_INET,
    abi::AF_INET6,
    abi::AF_UNSPEC, // = 0.
);

impl_debug!(Type, abi::SOCK_STREAM, abi::SOCK_DGRAM, abi::SOCK_RAW);

impl_debug!(
    Protocol,
    abi::IPPROTO_ICMP,
    abi::IPPROTO_ICMPV6,
    abi::IPPROTO_TCP,
    abi::IPPROTO_UDP,
);

#[repr(transparent)]
pub struct MaybeUninitSlice<'a> {
    vec: abi::iovec,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

unsafe impl<'a> Send for MaybeUninitSlice<'a> {}

unsafe impl<'a> Sync for MaybeUninitSlice<'a> {}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> MaybeUninitSlice<'a> {
        MaybeUninitSlice {
            vec: abi::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts(self.vec.iov_base.cast(), self.vec.iov_len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts_mut(self.vec.iov_base.cast(), self.vec.iov_len) }
    }
}

pub(crate) type Socket = c_int;

pub(crate) unsafe fn socket_from_raw(socket: Socket) -> crate::socket::Inner {
    crate::socket::Inner::from_raw_fd(socket)
}

pub(crate) fn socket_as_raw(socket: &crate::socket::Inner) -> Socket {
    socket.as_raw_fd()
}

pub(crate) fn socket_into_raw(socket: crate::socket::Inner) -> Socket {
    socket.into_raw_fd()
}

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<Socket> {
    syscall!(socket(family, ty, protocol))
}

pub(crate) fn bind(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(fd, addr.as_ptr(), addr.len() as _)).map(|_| ())
}

pub(crate) fn connect(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(connect(fd, addr.as_ptr(), addr.len())).map(|_| ())
}

pub(crate) fn poll_connect(socket: &crate::Socket, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();

    let mut pollfd = abi::pollfd {
        fd: socket.as_raw(),
        events: abi::POLLIN | abi::POLLOUT,
        revents: 0,
    };

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(io::ErrorKind::TimedOut.into());
        }

        let timeout = (timeout - elapsed).as_millis();
        let timeout = clamp(timeout, 1, c_int::max_value() as u128) as c_int;

        match syscall!(poll(&mut pollfd, 1, timeout)) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => {
                // Error or hang up indicates an error (or failure to connect).
                if (pollfd.revents & abi::POLLHUP) != 0 || (pollfd.revents & abi::POLLERR) != 0 {
                    match socket.take_error() {
                        Ok(Some(err)) => return Err(err),
                        Ok(None) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "no error set after POLLHUP",
                            ))
                        }
                        Err(err) => return Err(err),
                    }
                }
                return Ok(());
            }
            // Got interrupted, try again.
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

// TODO: use clamp from std lib, stable since 1.50.
fn clamp<T>(value: T, min: T, max: T) -> T
where
    T: Ord,
{
    if value <= min {
        min
    } else if value >= max {
        max
    } else {
        value
    }
}

pub(crate) fn listen(fd: Socket, backlog: c_int) -> io::Result<()> {
    syscall!(listen(fd, backlog)).map(|_| ())
}

pub(crate) fn accept(fd: Socket) -> io::Result<(Socket, SockAddr)> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| syscall!(accept(fd, storage.cast(), len))) }
}

pub(crate) fn getsockname(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| syscall!(getsockname(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn getpeername(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| syscall!(getpeername(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn try_clone(fd: Socket) -> io::Result<Socket> {
    syscall!(dup(fd))
}

pub(crate) fn set_nonblocking(fd: Socket, nonblocking: bool) -> io::Result<()> {
    if nonblocking {
        fcntl_add(fd, abi::F_GETFL, abi::F_SETFL, abi::O_NONBLOCK)
    } else {
        fcntl_remove(fd, abi::F_GETFL, abi::F_SETFL, abi::O_NONBLOCK)
    }
}

pub(crate) fn shutdown(fd: Socket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Write => abi::SHUT_WR,
        Shutdown::Read => abi::SHUT_RD,
        Shutdown::Both => abi::SHUT_RDWR,
    };
    syscall!(shutdown(fd, how)).map(|_| ())
}

pub(crate) fn recv(fd: Socket, buf: &mut [MaybeUninit<u8>], flags: c_int) -> io::Result<usize> {
    syscall!(recv(
        fd,
        buf.as_mut_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

pub(crate) fn recv_from(
    fd: Socket,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    // Safety: `recvfrom` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|addr, addrlen| {
            syscall!(recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                min(buf.len(), MAX_BUF_LEN),
                flags,
                addr.cast(),
                addrlen
            ))
            .map(|n| n as usize)
        })
    }
}

pub(crate) fn send(fd: Socket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    syscall!(send(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

pub(crate) fn send_to(fd: Socket, buf: &[u8], addr: &SockAddr, flags: c_int) -> io::Result<usize> {
    syscall!(sendto(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
        addr.as_ptr(),
        addr.len(),
    ))
    .map(|n| n as usize)
}

/// Wrapper around `getsockopt` to deal with platform specific timeouts.
pub(crate) fn timeout_opt(fd: Socket, opt: c_int, val: c_int) -> io::Result<Option<Duration>> {
    unsafe { getsockopt(fd, opt, val).map(from_timeval) }
}

fn from_timeval(duration: abi::timeval) -> Option<Duration> {
    if duration.tv_sec == 0 && duration.tv_usec == 0 {
        None
    } else {
        let sec = duration.tv_sec as u64;
        let nsec = (duration.tv_usec as u32) * 1000;
        Some(Duration::new(sec, nsec))
    }
}

/// Wrapper around `setsockopt` to deal with platform specific timeouts.
pub(crate) fn set_timeout_opt(
    fd: Socket,
    opt: c_int,
    val: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_timeval(duration);
    unsafe { setsockopt(fd, opt, val, duration) }
}

fn into_timeval(duration: Option<Duration>) -> abi::timeval {
    match duration {
        Some(duration) => abi::timeval {
            tv_sec: min(duration.as_secs(), abi::time_t::max_value() as u64) as abi::time_t,
            tv_usec: duration.subsec_micros() as abi::suseconds_t,
        },
        None => abi::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    }
}

pub(crate) fn set_tcp_keepalive(fd: Socket, keepalive: &TcpKeepalive) -> io::Result<()> {
    if let Some(time) = keepalive.time {
        let secs = into_secs(time);
        unsafe { setsockopt(fd, abi::IPPROTO_TCP, abi::TCP_KEEPIDLE, secs)? }
    }

    if let Some(interval) = keepalive.interval {
        let secs = into_secs(interval);
        unsafe { setsockopt(fd, abi::IPPROTO_TCP, abi::TCP_KEEPINTVL, secs)? }
    }

    if let Some(retries) = keepalive.retries {
        unsafe { setsockopt(fd, abi::IPPROTO_TCP, abi::TCP_KEEPCNT, retries as c_int)? }
    }

    Ok(())
}

fn into_secs(duration: Duration) -> c_int {
    min(duration.as_secs(), c_int::max_value() as u64) as c_int
}

/// Add `flag` to the current set flags of `F_GETFD`.
fn fcntl_add(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = syscall!(fcntl(fd, get_cmd, 0))?;
    let new = previous | flag;
    if new != previous {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Remove `flag` to the current set flags of `F_GETFD`.
fn fcntl_remove(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = syscall!(fcntl(fd, get_cmd, 0))?;
    let new = previous & !flag;
    if new != previous {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn getsockopt<T>(fd: Socket, opt: c_int, val: c_int) -> io::Result<T> {
    let mut payload: MaybeUninit<T> = MaybeUninit::uninit();
    let mut len = size_of::<T>() as abi::socklen_t;
    syscall!(getsockopt(
        fd,
        opt,
        val,
        payload.as_mut_ptr().cast(),
        &mut len,
    ))
    .map(|_| {
        debug_assert_eq!(len as usize, size_of::<T>());
        // Safety: `getsockopt` initialised `payload` for us.
        payload.assume_init()
    })
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn setsockopt<T>(
    fd: Socket,
    opt: c_int,
    val: c_int,
    payload: T,
) -> io::Result<()> {
    let payload = &payload as *const T as *const c_void;
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as abi::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    // `s_addr` is stored as BE on all machines, and the array is in BE order.
    // So the native endian conversion method is used so that it's never
    // swapped.
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(in_addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())
}

pub(crate) fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

/// Unix only API.
impl crate::Socket {
    /// Returns `true` if `listen(2)` was called on this socket by checking the
    /// `SO_ACCEPTCONN` option on this socket.
    #[cfg(all(feature = "all"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "all"))))]
    pub fn is_listener(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), abi::SOL_SOCKET, abi::SO_ACCEPTCONN).map(|v| v != 0)
        }
    }
}

impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> c_int {
        self.as_raw()
    }
}

impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> c_int {
        self.into_raw()
    }
}

impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: c_int) -> crate::Socket {
        crate::Socket::from_raw(fd)
    }
}

#[test]
fn in_addr_convertion() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let raw = to_in_addr(&ip);
    // NOTE: `in_addr` is packed on NetBSD and it's unsafe to borrow.
    let a = raw.s_addr;
    assert_eq!(a, u32::from_ne_bytes([127, 0, 0, 1]));
    assert_eq!(from_in_addr(raw), ip);

    let ip = Ipv4Addr::new(127, 34, 4, 12);
    let raw = to_in_addr(&ip);
    let a = raw.s_addr;
    assert_eq!(a, u32::from_ne_bytes([127, 34, 4, 12]));
    assert_eq!(from_in_addr(raw), ip);
}

#[test]
fn in6_addr_convertion() {
    let ip = Ipv6Addr::new(0x2000, 1, 2, 3, 4, 5, 6, 7);
    let raw = to_in6_addr(&ip);
    let want = [32, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7];
    assert_eq!(raw.s6_addr, want);
    assert_eq!(from_in6_addr(raw), ip);
}
