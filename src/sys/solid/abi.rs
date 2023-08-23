//! SOLID Sockets ABI, all renamed to align with *nixes
#![allow(non_camel_case_types)]
#![allow(dead_code)]
pub use libc::{c_char, c_int, c_long, c_short, c_uint, c_void, size_t, ssize_t};

pub const SOLID_NET_ERR_BASE: c_int = -2000;
pub const EINPROGRESS: c_int = SOLID_NET_ERR_BASE - libc::EINPROGRESS;

pub const AF_INET6: i32 = 10;
pub const AF_INET: i32 = 2;
pub const AF_UNSPEC: i32 = 0;
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_IPV6: i32 = 41;
pub const IPPROTO_ICMPV6: i32 = 58;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPV6_ADD_MEMBERSHIP: i32 = 12;
pub const IPV6_DROP_MEMBERSHIP: i32 = 13;
pub const IPV6_MULTICAST_LOOP: i32 = 19;
pub const IPV6_MULTICAST_HOPS: i32 = 18;
pub const IPV6_MULTICAST_IF: i32 = 17;
pub const IPV6_UNICAST_HOPS: i32 = 4;
pub const IPV6_V6ONLY: i32 = 27;
pub const IP_TTL: i32 = 2;
pub const IP_TOS: i32 = 1;
pub const IP_MULTICAST_TTL: i32 = 5;
pub const IP_MULTICAST_IF: i32 = 6;
pub const IP_MULTICAST_LOOP: i32 = 7;
pub const IP_ADD_MEMBERSHIP: i32 = 3;
pub const IP_DROP_MEMBERSHIP: i32 = 4;
pub const SHUT_RD: i32 = 0;
pub const SHUT_RDWR: i32 = 2;
pub const SHUT_WR: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_RAW: i32 = 3;
pub const SOL_SOCKET: i32 = 4095;
pub const SO_BROADCAST: i32 = 32;
pub const SO_ACCEPTCONN: i32 = 2;
pub const SO_ERROR: i32 = 4103;
pub const SO_RCVTIMEO: i32 = 4102;
pub const SO_REUSEADDR: i32 = 4;
pub const SO_KEEPALIVE: i32 = 8;
pub const SO_LINGER: i32 = 128;
pub const SO_SNDTIMEO: i32 = 4101;
pub const SO_RCVBUF: i32 = 0x1002;
pub const SO_SNDBUF: i32 = 0x1005;
pub const SO_TYPE: i32 = 0x1008;
pub const TCP_NODELAY: i32 = 1;
pub const TCP_KEEPIDLE: i32 = 3;
pub const TCP_KEEPINTVL: i32 = 4;
pub const TCP_KEEPCNT: i32 = 5;
pub const MSG_PEEK: c_int = 1;
pub const MSG_OOB: c_int = 4;
pub const FIONBIO: c_long = 0x8008667eu32 as c_long;
pub const EAI_NONAME: i32 = -2200;
pub const EAI_SERVICE: i32 = -2201;
pub const EAI_FAIL: i32 = -2202;
pub const EAI_MEMORY: i32 = -2203;
pub const EAI_FAMILY: i32 = -2204;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const O_NONBLOCK: i32 = 1;

pub type sa_family_t = u8;
pub type socklen_t = u32;
pub type in_addr_t = u32;
pub type in_port_t = u16;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ip_mreq {
    pub imr_multiaddr: in_addr,
    pub imr_interface: in_addr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipv6_mreq {
    pub ipv6mr_multiaddr: in6_addr,
    pub ipv6mr_interface: c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: c_int,
    pub msg_control: *mut c_void,
    pub msg_controllen: socklen_t,
    pub msg_flags: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub sa_len: u8,
    pub sa_family: sa_family_t,
    pub sa_data: [c_char; 14usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub sin_len: u8,
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [c_char; 8usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_len: u8,
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_storage {
    pub s2_len: u8,
    pub ss_family: sa_family_t,
    pub s2_data1: [c_char; 2usize],
    pub s2_data2: [u32; 3usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct linger {
    /// option on/off
    pub l_onoff: c_int,
    /// linger time in seconds
    pub l_linger: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

pub type time_t = c_long;
pub type suseconds_t = c_long;

pub type PollMask = c_short;
pub const POLLIN: PollMask = 0x1;
pub const POLLOUT: PollMask = 0x2;
pub const POLLERR: PollMask = 0x4;
pub const POLLNVAL: PollMask = 0x8;
pub const POLLRDNORM: PollMask = 0x10;
pub const POLLRDBAND: PollMask = 0x20;
pub const POLLPRI: PollMask = 0x40;
pub const POLLWRNORM: PollMask = 0x80;
pub const POLLWRBAND: PollMask = 0x100;
pub const POLLHUP: PollMask = 0x200;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pollfd {
    pub fd: c_int,
    pub events: PollMask,
    pub revents: PollMask,
}

extern "C" {
    #[link_name = "SOLID_NET_StrError"]
    pub fn strerror(errnum: c_int) -> *const c_char;

    pub fn SOLID_NET_GetLastError() -> c_int;

    #[link_name = "SOLID_NET_Accept"]
    pub fn accept(s: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int;

    #[link_name = "SOLID_NET_Bind"]
    pub fn bind(s: c_int, name: *const sockaddr, namelen: socklen_t) -> c_int;

    #[link_name = "SOLID_NET_Connect"]
    pub fn connect(s: c_int, name: *const sockaddr, namelen: socklen_t) -> c_int;

    #[link_name = "SOLID_NET_Close"]
    pub fn close(s: c_int) -> c_int;

    #[link_name = "SOLID_NET_Dup"]
    pub fn dup(s: c_int) -> c_int;

    #[link_name = "SOLID_NET_GetPeerName"]
    pub fn getpeername(s: c_int, name: *mut sockaddr, namelen: *mut socklen_t) -> c_int;

    #[link_name = "SOLID_NET_GetSockName"]
    pub fn getsockname(s: c_int, name: *mut sockaddr, namelen: *mut socklen_t) -> c_int;

    #[link_name = "SOLID_NET_GetSockOpt"]
    pub fn getsockopt(
        s: c_int,
        level: c_int,
        optname: c_int,
        optval: *mut c_void,
        optlen: *mut socklen_t,
    ) -> c_int;

    #[link_name = "SOLID_NET_SetSockOpt"]
    pub fn setsockopt(
        s: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: socklen_t,
    ) -> c_int;

    #[link_name = "SOLID_NET_Ioctl"]
    pub fn ioctl(s: c_int, cmd: c_long, argp: *mut c_void) -> c_int;

    #[link_name = "SOLID_NET_Listen"]
    pub fn listen(s: c_int, backlog: c_int) -> c_int;

    #[link_name = "SOLID_NET_Recv"]
    pub fn recv(s: c_int, mem: *mut c_void, len: size_t, flags: c_int) -> ssize_t;

    #[link_name = "SOLID_NET_Read"]
    pub fn read(s: c_int, mem: *mut c_void, len: size_t) -> ssize_t;

    #[link_name = "SOLID_NET_Readv"]
    pub fn readv(s: c_int, bufs: *const iovec, bufcnt: c_int) -> ssize_t;

    #[link_name = "SOLID_NET_RecvFrom"]
    pub fn recvfrom(
        s: c_int,
        mem: *mut c_void,
        len: size_t,
        flags: c_int,
        from: *mut sockaddr,
        fromlen: *mut socklen_t,
    ) -> ssize_t;

    #[link_name = "SOLID_NET_Send"]
    pub fn send(s: c_int, mem: *const c_void, len: size_t, flags: c_int) -> ssize_t;

    #[link_name = "SOLID_NET_SendMsg"]
    pub fn sendmsg(s: c_int, message: *const msghdr, flags: c_int) -> ssize_t;

    #[link_name = "SOLID_NET_SendTo"]
    pub fn sendto(
        s: c_int,
        mem: *const c_void,
        len: size_t,
        flags: c_int,
        to: *const sockaddr,
        tolen: socklen_t,
    ) -> ssize_t;

    #[link_name = "SOLID_NET_Shutdown"]
    pub fn shutdown(s: c_int, how: c_int) -> c_int;

    #[link_name = "SOLID_NET_Socket"]
    pub fn socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int;

    #[link_name = "SOLID_NET_Write"]
    pub fn write(s: c_int, mem: *const c_void, len: size_t) -> ssize_t;

    #[link_name = "SOLID_NET_Writev"]
    pub fn writev(s: c_int, bufs: *const iovec, bufcnt: c_int) -> ssize_t;

    #[link_name = "SOLID_NET_Fcntl"]
    pub fn fcntl(fd: c_int, cmd: c_int, val: c_int) -> c_int;

    #[link_name = "SOLID_NET_Poll"]
    pub fn poll(fds: *mut pollfd, nfds: c_uint, timeout: c_int) -> c_int;
}
