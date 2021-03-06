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
use crypto::Crypto;
use error::{Result, TiTunError};
use futures::{Async, Future, Poll, Stream};
use futures::task;
use script_runner::ScriptRunner;
use std::cell::RefCell;
use std::convert::From;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::rc::Rc;
use systemd::notify_ready;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::{Core, PollEvented};
use tokio_signal;
use tun::Tun;

/// Run titun with some configuration. Will not return unless an error happens.
pub fn run(config: &Config) -> Result<()> {
    let mut core = Core::new()?;
    let handle = core.handle();

    assert!(config.peer.is_some() || config.bind.is_some());

    let bind = config.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let sock = UdpSocket::bind(&bind, &handle)?;
    info!("Bind to {}.", sock.local_addr()?);

    let tun = Tun::create(config.dev_name.as_ref().map(|n| n.as_str()))?;
    let tun_name = tun.get_name().to_string();
    info!("Tun device created: {}.", &tun_name);
    tun.set_nonblocking(true)?;

    if let Some(ref on_up) = config.on_up {
        ScriptRunner::new().env("TUN", &tun_name).run(on_up.as_bytes())?;
    }

    let tun = PollEvented::new(tun, &handle)?;

    // If peer is set, we send packets to it. Otherwise we send to who ever
    // most recently send us an authenticated packet.
    let remote_addr: Rc<RefCell<Option<SocketAddr>>> = Rc::new(RefCell::new(None));
    let remote_addr1 = if config.peer.is_some() {
        *remote_addr.borrow_mut() = config.peer;
        None
    } else {
        Some(remote_addr.clone())
    };

    let crypto = Crypto::new(config.key.clone(), config.max_diff);

    let common = Rc::new(RefCell::new(Common {
        crypto: crypto,
        sock: sock,
        tun: tun,
        buf: vec![0u8; config.bufsize],
    }));

    let sock_to_tun = SockToTun {
        common: common.clone(),
        remote_addr: remote_addr1,
        buf_to_write: None,
    };

    let tun_to_sock = TunToSock {
        common: common,
        remote_addr: remote_addr,
        buf_to_send: None,
    };

    let titun_fut = sock_to_tun.select(tun_to_sock).then(|r| match r {
        Err((e, _)) => Err(e),
        Ok(_) => unreachable!(),
    });

    let sigint = tokio_signal::unix::Signal::new(tokio_signal::unix::SIGINT, &handle);
    let sigint = core.run(sigint)?;
    let sigterm = tokio_signal::unix::Signal::new(tokio_signal::unix::SIGTERM, &handle);
    let sigterm = core.run(sigterm)?;

    let signal_fut = sigint.select(sigterm).map_err(From::from).for_each(|s| {
        info!("Received signal {}, exiting.", s);
        if let Some(ref on_down) = config.on_down {
            ScriptRunner::new().env("TUN", &tun_name).run(on_down.as_bytes())?;
        }
        Err(TiTunError::GracefulExit)
    });

    notify_ready();

    core.run(titun_fut.select(signal_fut).then(|r| match r {
        Err((TiTunError::GracefulExit, _)) => Ok(()),
        Err((e, _)) => Err(e),
        Ok(_) => unreachable!(),
    }))
}

struct Common {
    crypto: Crypto,
    sock: UdpSocket,
    tun: PollEvented<Tun>,
    buf: Vec<u8>,
}

struct SockToTun {
    common: Rc<RefCell<Common>>,
    remote_addr: Option<Rc<RefCell<Option<SocketAddr>>>>,
    buf_to_write: Option<Vec<u8>>,
}

// poll and try_nb! are somewhat like async/await...only the function continues from the start,
// not where it was interrupted.
//
// much easier to write than closures.

impl Future for SockToTun {
    type Item = ();
    type Error = TiTunError;

    fn poll(&mut self) -> Poll<(), TiTunError> {
        let mut common = self.common.borrow_mut();
        // Explicit deref_mut to get mutable references to disjoint fields.
        let mut common = common.deref_mut();

        // Do not loop forever, to avoid starvation. See
        // https://github.com/tokio-rs/tokio-core/issues/165
        for _ in 0..128 {
            self.buf_to_write = if let Some(ref b) = self.buf_to_write {
                try_nb!(common.tun.write(b.as_slice()));
                None
            } else {
                None
            };

            let (l, addr) = try_nb!(common.sock.recv_from(common.buf.as_mut()));
            if let Some(p) = common.crypto.decrypt(common.buf[..l].as_ref()) {
                if let Some(ref r) = self.remote_addr {
                    let mut rr = r.borrow_mut();
                    if *rr != Some(addr) {
                        *rr = Some(addr);
                        info!("Peer address set to {}", addr);
                    }
                }
                self.buf_to_write = Some(p);
            } else {
                debug!("decryption failed");
            }
        }

        task::park().unpark();
        Ok(Async::NotReady)
    }
}

struct TunToSock {
    common: Rc<RefCell<Common>>,
    remote_addr: Rc<RefCell<Option<SocketAddr>>>,
    buf_to_send: Option<Vec<u8>>,
}

impl Future for TunToSock {
    type Item = ();
    type Error = TiTunError;

    fn poll(&mut self) -> Poll<(), TiTunError> {
        let mut common = self.common.borrow_mut();
        // Explicit deref_mut to get mutable references to disjoint fields.
        let mut common = common.deref_mut();

        for _ in 0..128 {
            self.buf_to_send = if let Some(ref b) = self.buf_to_send {
                if let Some(ref a) = *self.remote_addr.borrow() {
                    try_nb!(common.sock.send_to(b.as_ref(), a));
                }
                None
            } else {
                None
            };

            let l = try_nb!(common.tun.read(common.buf.as_mut()));
            self.buf_to_send = Some(common.crypto.encrypt(common.buf[..l].as_ref()));
        }

        task::park().unpark();
        Ok(Async::NotReady)
    }
}
