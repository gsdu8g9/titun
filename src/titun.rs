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

use config::Config;
use crypto::{decrypt, encrypt};
use futures::{Future, Poll};
use map_err_io::MapErrIo;
use script_runner::ScriptRunner;
use sodiumoxide::crypto::secretbox::Key;
use std::cell::RefCell;
use std::io::{Error, Read, Result, Write};
use std::net::SocketAddr;
use std::rc::Rc;
use systemd_notify::systemd_notify_ready;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::{Core, PollEvented};
use tun::Tun;

pub fn run(config: Config) -> Result<()> {
    assert!(config.peer.is_some() || config.bind.is_some());

    let bind = config.bind.unwrap_or("0.0.0.0:0".to_string());
    let sock = ::std::net::UdpSocket::bind(bind.as_str())?;
    info!("Bind succeeded.");
    sock.set_nonblocking(true)?;

    let tun = Tun::create(None)?;
    info!("Tun device created: {}.", tun.get_name());
    tun.set_nonblocking(true)?;

    if let Some(script) = config.config_script {
        ScriptRunner::new().env("TUN", tun.get_name()).run(script.as_bytes())?;
    }

    systemd_notify_ready();

    let mut core = Core::new()?;
    let handle = core.handle();

    let tun = Rc::new(RefCell::new(PollEvented::new(tun, &handle)?));
    let sock = Rc::new(::tokio_core::net::UdpSocket::from_socket(sock, &handle)?);

    // If peer is set, we send packets to it. Otherwise we send to who ever
    // most recently send us an authenticated packet.
    let remote_addr: Rc<RefCell<Option<SocketAddr>>> = Rc::new(RefCell::new(None));
    let remote_addr1 = if let Some(peer) = config.peer {
        *remote_addr.borrow_mut() = Some(peer.parse().map_err_io()?);
        None
    } else {
        Some(remote_addr.clone())
    };

    let sock_to_tun = SockToTun {
        key: config.key.clone(),
        sock: sock.clone(),
        tun: tun.clone(),
        remote_addr: remote_addr1,
        buf: vec![0u8; config.bufsize],
        buf_to_write: None,
    };

    let tun_to_sock = TunToSock {
        key: config.key,
        sock: sock,
        tun: tun,
        remote_addr: remote_addr,
        buf: vec![0u8; config.bufsize],
        buf_to_send: None,
    };

    core.run(sock_to_tun.select(tun_to_sock).then(|r| {
        match r {
            Err((e, _)) => Err(e),
            Ok(_) => unreachable!(),
        }
    }))
}

struct SockToTun {
    key: Key,
    sock: Rc<UdpSocket>,
    // Don't actually need mutable reference, but make std::io::Write happy.
    tun: Rc<RefCell<PollEvented<Tun>>>,
    remote_addr: Option<Rc<RefCell<Option<SocketAddr>>>>,
    buf: Vec<u8>,
    buf_to_write: Option<Vec<u8>>,
}

// poll and try_nb! are somewhat like async/await...
//
// but MUCH easier to write than closures.

// TODO rate-limit / merge duplicated logging?

impl Future for SockToTun {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        loop {
            self.buf_to_write = if let Some(ref b) = self.buf_to_write {
                try_nb!(self.tun.borrow_mut().write(b.as_slice()));
                None
            } else {
                None
            };

            let (l, addr) = try_nb!(self.sock.recv_from(self.buf.as_mut()));
            if let Some(p) = decrypt(&self.key, self.buf[..l].as_ref()) {
                if let Some(ref r) = self.remote_addr {
                    *r.borrow_mut() = Some(addr);
                }
                self.buf_to_write = Some(p);
            } else {
                warn!("decryption failed");
            }
        }
    }
}

struct TunToSock {
    key: Key,
    sock: Rc<UdpSocket>,
    // Don't actually need mutable reference, but make std::io::Read happy.
    tun: Rc<RefCell<PollEvented<Tun>>>,
    remote_addr: Rc<RefCell<Option<SocketAddr>>>,
    buf: Vec<u8>,
    buf_to_send: Option<Vec<u8>>,
}

impl Future for TunToSock {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        loop {
            self.buf_to_send = if let Some(ref b) = self.buf_to_send {
                if let Some(ref a) = *self.remote_addr.borrow() {
                    try_nb!(self.sock.send_to(b.as_ref(), a));
                } else {
                    warn!("got packet but don't know where to send it, discard");
                }
                None
            } else {
                None
            };

            let l = try_nb!(self.tun.borrow_mut().read(self.buf.as_mut()));
            self.buf_to_send = Some(encrypt(&self.key, self.buf[..l].as_ref()));
        }
    }
}
