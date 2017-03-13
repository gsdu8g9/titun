// Copyright 2017 Sopium

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

extern crate mio;
extern crate nix;

use self::mio::{Evented, Poll, PollOpt, Ready, Token};
use self::mio::unix::EventedFd;
use self::nix::fcntl::{self, FcntlArg, OFlag, fcntl, open};
use self::nix::libc::{c_int, c_short};
use self::nix::sys::stat::Mode;
use self::nix::unistd::{close, read, write};
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

ioctl!(write tunsetiff with b'T', 202; c_int);

const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;

#[repr(C)]
struct ifreq {
    name: [u8; 16], // Use u8 becuase that's what CString and CStr wants.
    flags: c_short,
}

/// A linux tun device.
#[derive(Debug)]
pub struct Tun {
    fd: i32,
    name: String,
}

/// The file descriptor will be closed when the Tun is dropped.
impl Drop for Tun {
    fn drop(&mut self) {
        // Ignore error...
        let _ = close(self.fd);
    }
}

impl Tun {
    /// Create a tun device.

    /// O_CLOEXEC, IFF_NO_PI.
    pub fn create(name: Option<&str>) -> Result<Tun> {
        if let Some(n) = name {
            // IFNAMESIZ is 16.
            if n.len() > 15 {
                return Err(Error::new(ErrorKind::InvalidInput, "device name is too long"));
            }
        }

        let name =
            CString::new(name.unwrap_or("")).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
        let name = name.as_bytes_with_nul();

        let fd = open("/dev/net/tun",
                      fcntl::O_RDWR | fcntl::O_CLOEXEC,
                      Mode::empty())?;

        let mut ifr = ifreq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
        };

        ifr.name[..name.len()].copy_from_slice(name);

        unsafe { tunsetiff(fd, &ifr as *const ifreq as *const c_int) }?;

        let namelen = ifr.name
            .iter()
            .position(|x| *x == 0)
            .unwrap() + 1;

        let name = CStr::from_bytes_with_nul(&ifr.name[..namelen])
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        Ok(Tun {
            fd: fd,
            name: name,
        })
    }

    /// Get name of this device. Should be the same name if you have
    /// passed one in when createing the device.
    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<()> {
        let flags = fcntl(self.fd, FcntlArg::F_GETFL)?;
        let flags = OFlag::from_bits(flags).unwrap();
        let flags = if nb {
            flags | fcntl::O_NONBLOCK
        } else {
            flags & !fcntl::O_NONBLOCK
        };
        fcntl(self.fd, FcntlArg::F_SETFL(flags))?;
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

impl Tun {
    /// Read a packet from the tun device.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(read(self.fd, buf)?)
    }

    /// Write a packet to tun device.
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(write(self.fd, buf)?)
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Tun::read(self, buf)
    }
}

impl<'a> Read for &'a Tun {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Tun::read(self, buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Tun::write(self, buf)
    }

    /// flush() for Tun is a no-op.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a Tun {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Tun::write(self, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Evented for Tun {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> Result<()> {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}
