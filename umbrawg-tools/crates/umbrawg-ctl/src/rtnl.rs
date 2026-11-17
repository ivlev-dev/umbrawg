use std::ffi::CString;
use std::io;
use std::mem::size_of;

use crate::error::Error;

const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

const UMBRAWG_KIND: &str = "umbrawg";
const HEADER_LEN: usize = 16;
const IFINFO_LEN: usize = 16;
const RECEIVE_TIMEOUT_SECONDS: libc::time_t = 5;

pub fn get_kernel_interfaces() -> Result<Vec<String>, Error> {
    let socket = Socket::open()?;
    let payload = ifinfo(0, libc::AF_UNSPEC as u8);
    let request = message(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &payload);
    socket.send(&request)?;
    let mut interfaces = Vec::new();
    let mut finished = false;
    while !finished {
        let buffer = socket.receive()?;
        let mut offset = 0;
        while offset + HEADER_LEN <= buffer.len() {
            let length = u32::from_ne_bytes(
                buffer[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::Protocol("truncated netlink header".to_owned()))?,
            ) as usize;
            if length < HEADER_LEN || offset + length > buffer.len() {
                return Err(Error::Protocol("invalid netlink message length".to_owned()));
            }
            let kind = u16::from_ne_bytes(
                buffer[offset + 4..offset + 6]
                    .try_into()
                    .map_err(|_| Error::Protocol("truncated netlink header".to_owned()))?,
            );
            match kind {
                NLMSG_DONE => {
                    finished = true;
                    break;
                }
                NLMSG_ERROR => {
                    return Err(error_from_message(&buffer[offset..offset + length]));
                }
                NLMSG_OVERRUN => {
                    return Err(Error::Protocol("netlink dump overrun".to_owned()));
                }
                RTM_NEWLINK => {
                    let payload = &buffer[offset + HEADER_LEN..offset + length];
                    if let Some(name) = interface_name(payload) {
                        interfaces.push(name);
                    }
                }
                _ => {}
            }
            offset += aligned(length);
        }
    }
    interfaces.sort();
    interfaces.dedup();
    Ok(interfaces)
}

pub fn create_interface(name: &str, kind: &str) -> Result<(), Error> {
    crate::uapi::validate_interface_name(name)?;
    let mut payload = ifinfo(0, libc::AF_UNSPEC as u8);
    payload.extend(attribute(IFLA_IFNAME, &nul_terminated(name)));
    payload.extend(attribute(
        IFLA_LINKINFO,
        &attribute(IFLA_INFO_KIND, &nul_terminated(kind)),
    ));
    let request = message(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        1,
        &payload,
    );
    let socket = Socket::open()?;
    socket.send(&request)?;
    socket.acknowledge()
}

pub fn delete_interface(name: &str) -> Result<(), Error> {
    crate::uapi::validate_interface_name(name)?;
    let name =
        CString::new(name).map_err(|_| Error::InvalidInterfaceName("embedded NUL".to_owned()))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(Error::InterfaceNotFound(
            name.to_string_lossy().into_owned(),
        ));
    }
    let payload = ifinfo(index as i32, libc::AF_UNSPEC as u8);
    let request = message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, 1, &payload);
    let socket = Socket::open()?;
    socket.send(&request)?;
    socket.acknowledge()
}

fn interface_name(payload: &[u8]) -> Option<String> {
    if payload.len() < IFINFO_LEN {
        return None;
    }
    let attributes = &payload[IFINFO_LEN..];
    let kind = find_attribute(attributes, IFLA_LINKINFO)
        .and_then(|nested| find_attribute(nested, IFLA_INFO_KIND))
        .and_then(text_attribute)?;
    if kind != UMBRAWG_KIND {
        return None;
    }
    find_attribute(attributes, IFLA_IFNAME).and_then(text_attribute)
}

fn find_attribute(data: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let length = u16::from_ne_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(data[offset + 2..offset + 4].try_into().ok()?) & 0x3fff;
        if length < 4 || offset + length > data.len() {
            return None;
        }
        if kind == wanted {
            return Some(&data[offset + 4..offset + length]);
        }
        offset += aligned(length);
    }
    None
}

fn text_attribute(data: &[u8]) -> Option<String> {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[..end])
        .ok()
        .map(ToOwned::to_owned)
}

fn ifinfo(index: i32, family: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(IFINFO_LEN);
    payload.push(family);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_ne_bytes());
    payload.extend_from_slice(&index.to_ne_bytes());
    payload.extend_from_slice(&0u32.to_ne_bytes());
    payload.extend_from_slice(&0u32.to_ne_bytes());
    payload
}

fn attribute(kind: u16, data: &[u8]) -> Vec<u8> {
    let length = 4 + data.len();
    let mut buffer = Vec::with_capacity(aligned(length));
    buffer.extend_from_slice(&(length as u16).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(data);
    while buffer.len() % 4 != 0 {
        buffer.push(0);
    }
    buffer
}

fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let length = HEADER_LEN + payload.len();
    let mut buffer = Vec::with_capacity(length);
    buffer.extend_from_slice(&(length as u32).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(&flags.to_ne_bytes());
    buffer.extend_from_slice(&sequence.to_ne_bytes());
    buffer.extend_from_slice(&0u32.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer
}

fn error_from_message(data: &[u8]) -> Error {
    match error_code(data) {
        Ok(0) => Error::Protocol("unexpected empty netlink error".to_owned()),
        Ok(code) => Error::Io(io::Error::from_raw_os_error(code.abs())),
        Err(error) => error,
    }
}

fn error_code(data: &[u8]) -> Result<i32, Error> {
    if data.len() < HEADER_LEN + 4 {
        return Err(Error::Protocol("truncated netlink error".to_owned()));
    }
    let bytes: [u8; 4] = data[HEADER_LEN..HEADER_LEN + 4]
        .try_into()
        .map_err(|_| Error::Protocol("truncated netlink error".to_owned()))?;
    Ok(i32::from_ne_bytes(bytes))
}

fn aligned(length: usize) -> usize {
    (length + 3) & !3
}

fn nul_terminated(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

struct Socket {
    fd: libc::c_int,
}

impl Socket {
    fn open() -> Result<Self, Error> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let socket = Self { fd };
        let address = {
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;
            address
        };
        let result = unsafe {
            libc::bind(
                fd,
                &address as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let timeout = libc::timeval {
            tv_sec: RECEIVE_TIMEOUT_SECONDS,
            tv_usec: 0,
        };
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(socket)
    }

    fn send(&self, data: &[u8]) -> Result<(), Error> {
        let sent =
            unsafe { libc::send(self.fd, data.as_ptr() as *const libc::c_void, data.len(), 0) };
        if sent < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        if sent as usize != data.len() {
            return Err(Error::Io(io::Error::from(io::ErrorKind::WriteZero)));
        }
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![0u8; 65536];
        let received = unsafe {
            libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        buffer.truncate(received as usize);
        Ok(buffer)
    }

    fn acknowledge(&self) -> Result<(), Error> {
        for _ in 0..16 {
            let buffer = self.receive()?;
            let mut offset = 0;
            while offset + HEADER_LEN <= buffer.len() {
                let length = u32::from_ne_bytes(
                    buffer[offset..offset + 4]
                        .try_into()
                        .map_err(|_| Error::Protocol("truncated netlink header".to_owned()))?,
                ) as usize;
                if length < HEADER_LEN || offset + length > buffer.len() {
                    return Err(Error::Protocol("invalid netlink message length".to_owned()));
                }
                let kind = u16::from_ne_bytes(
                    buffer[offset + 4..offset + 6]
                        .try_into()
                        .map_err(|_| Error::Protocol("truncated netlink header".to_owned()))?,
                );
                if kind == NLMSG_ERROR {
                    let code = error_code(&buffer[offset..offset + length])?;
                    if code == 0 {
                        return Ok(());
                    }
                    return Err(Error::Io(io::Error::from_raw_os_error(code.abs())));
                }
                offset += aligned(length);
            }
        }
        Err(Error::Protocol(
            "no netlink acknowledgement received".to_owned(),
        ))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout() {
        let payload = ifinfo(7, libc::AF_UNSPEC as u8);
        let data = message(RTM_GETLINK, NLM_F_REQUEST, 42, &payload);
        assert_eq!(
            u32::from_ne_bytes(data[0..4].try_into().expect("header")),
            (HEADER_LEN + IFINFO_LEN) as u32
        );
        assert_eq!(
            u16::from_ne_bytes(data[4..6].try_into().expect("header")),
            RTM_GETLINK
        );
        assert_eq!(
            u16::from_ne_bytes(data[6..8].try_into().expect("header")),
            NLM_F_REQUEST
        );
        assert_eq!(
            u32::from_ne_bytes(data[8..12].try_into().expect("header")),
            42
        );
        assert_eq!(
            i32::from_ne_bytes(data[20..24].try_into().expect("ifinfo")),
            7
        );
    }

    #[test]
    fn attribute_padding() {
        let data = attribute(IFLA_IFNAME, b"uwg0\0");
        assert_eq!(u16::from_ne_bytes(data[0..2].try_into().expect("attr")), 9);
        assert_eq!(data.len(), 12);
        assert_eq!(find_attribute(&data, IFLA_IFNAME), Some(&b"uwg0\0"[..]));
    }

    #[test]
    fn parses_link_message() {
        let mut payload = ifinfo(3, libc::AF_UNSPEC as u8);
        payload.extend(attribute(IFLA_IFNAME, b"uwg0\0"));
        let mut info = attribute(IFLA_INFO_KIND, b"umbrawg\0");
        info = attribute(IFLA_LINKINFO, &info);
        payload.extend(info);
        assert_eq!(interface_name(&payload), Some("uwg0".to_owned()));
    }

    #[test]
    fn ignores_foreign_link_kind() {
        let mut payload = ifinfo(3, libc::AF_UNSPEC as u8);
        payload.extend(attribute(IFLA_IFNAME, b"eth0\0"));
        let info = attribute(IFLA_INFO_KIND, b"veth\0");
        payload.extend(attribute(IFLA_LINKINFO, &info));
        assert_eq!(interface_name(&payload), None);
    }

    #[test]
    fn interface_name_validation_is_shared() {
        assert!(crate::uapi::validate_interface_name("uwg0").is_ok());
        assert!(crate::uapi::validate_interface_name("bad/name").is_err());
    }
}
