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
use futures::{Future, Poll, Stream};
use script_runner::ScriptRunner;
use std::cell::RefCell;
use std::convert::From;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::rc::Rc;
use systemd_notify::systemd_notify_ready;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::{Core, Handle, PollEvented};
use tokio_signal;
use tun::Tun;

/// Return a future that can be run to run the tunnel.
pub fn titun_get_future(config: &Config,
                        handle: &Handle)
                        -> Result<Box<Future<Item = (), Error = TiTunError>>> {
    assert!(config.peer.is_some() || config.bind.is_some());

    let bind = config.bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let sock = UdpSocket::bind(&bind, handle)?;
    info!("Bind to {}.", sock.local_addr()?);

    let tun = Tun::create(config.dev_name.as_ref().map(|n| n.as_str()))?;
    info!("Tun device created: {}.", tun.get_name());
    tun.set_nonblocking(true)?;

    if let Some(ref script) = config.config_script {
        ScriptRunner::new().env("TUN", tun.get_name()).run(script.as_bytes())?;
    }

    let tun = Rc::new(RefCell::new(PollEvented::new(tun, handle)?));
    let sock = Rc::new(sock);

    // If peer is set, we send packets to it. Otherwise we send to who ever
    // most recently send us an authenticated packet.
    let remote_addr: Rc<RefCell<Option<SocketAddr>>> = Rc::new(RefCell::new(None));
    let remote_addr1 = if config.peer.is_some() {
        *remote_addr.borrow_mut() = config.peer;
        None
    } else {
        Some(remote_addr.clone())
    };

    let crypto = Rc::new(Crypto::new(config.key.clone(), config.max_diff));
    let log_dedup = Rc::new(RefCell::new(LogDedup::new()));

    let sock_to_tun = SockToTun {
        crypto: crypto.clone(),
        sock: sock.clone(),
        tun: tun.clone(),
        remote_addr: remote_addr1,
        log_dedup: log_dedup.clone(),
        buf: vec![0u8; config.bufsize],
        buf_to_write: None,
    };

    let tun_to_sock = TunToSock {
        crypto: crypto,
        sock: sock,
        tun: tun,
        remote_addr: remote_addr,
        log_dedup: log_dedup,
        buf: vec![0u8; config.bufsize],
        buf_to_send: None,
    };

    Ok(Box::new(sock_to_tun.select(tun_to_sock).then(|r| {
        match r {
            Err((e, _)) => Err(e),
            Ok(_) => unreachable!(),
        }
    })))
}

/// Run titun with some configuration. Will not return unless an error happens.
pub fn run(config: &Config) -> Result<()> {
    let mut core = Core::new()?;
    let handle = core.handle();

    let titun_fut = titun_get_future(config, &handle)?;

    let sigint = tokio_signal::unix::Signal::new(tokio_signal::unix::SIGINT, &handle);
    let sigint = core.run(sigint)?;
    let sigterm = tokio_signal::unix::Signal::new(tokio_signal::unix::SIGTERM, &handle);
    let sigterm = core.run(sigterm)?;

    let signal_fut = sigint.select(sigterm).map_err(From::from).for_each(|s| {
        info!("Received signal {}, exiting.", s);
        Err(TiTunError::GracefulExit)
    });

    systemd_notify_ready();

    core.run(titun_fut.select(signal_fut).then(|r| {
        match r {
            Err((TiTunError::GracefulExit, _)) => Ok(()),
            Err((e, _)) => Err(e),
            Ok(_) => unreachable!(),
        }
    }))
}

struct SockToTun {
    crypto: Rc<Crypto>,
    sock: Rc<UdpSocket>,
    // Don't actually need mutable reference, but make std::io::Write happy.
    tun: Rc<RefCell<PollEvented<Tun>>>,
    remote_addr: Option<Rc<RefCell<Option<SocketAddr>>>>,
    log_dedup: Rc<RefCell<LogDedup>>,
    buf: Vec<u8>,
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
        loop {
            self.buf_to_write = if let Some(ref b) = self.buf_to_write {
                try_nb!(self.tun.borrow_mut().write(b.as_slice()));
                None
            } else {
                None
            };

            let (l, addr) = try_nb!(self.sock.recv_from(self.buf.as_mut()));
            if let Some(p) = self.crypto.decrypt(self.buf[..l].as_ref()) {
                if let Some(ref r) = self.remote_addr {
                    let mut rr = r.borrow_mut();
                    if *rr != Some(addr) {
                        *rr = Some(addr);
                        info!("Peer address set to {}", addr);
                    }
                }
                self.buf_to_write = Some(p);
            } else {
                self.log_dedup.borrow_mut().warn("decryption failed");
            }
        }
    }
}

struct TunToSock {
    crypto: Rc<Crypto>,
    sock: Rc<UdpSocket>,
    // Don't actually need mutable reference, but make std::io::Read happy.
    tun: Rc<RefCell<PollEvented<Tun>>>,
    remote_addr: Rc<RefCell<Option<SocketAddr>>>,
    log_dedup: Rc<RefCell<LogDedup>>,
    buf: Vec<u8>,
    buf_to_send: Option<Vec<u8>>,
}

impl Future for TunToSock {
    type Item = ();
    type Error = TiTunError;

    fn poll(&mut self) -> Poll<(), TiTunError> {
        loop {
            self.buf_to_send = if let Some(ref b) = self.buf_to_send {
                if let Some(ref a) = *self.remote_addr.borrow() {
                    try_nb!(self.sock.send_to(b.as_ref(), a));
                } else {
                    self.log_dedup
                        .borrow_mut()
                        .warn("Got packet but don't know peer address.");
                }
                None
            } else {
                None
            };

            let l = try_nb!(self.tun.borrow_mut().read(self.buf.as_mut()));
            self.buf_to_send = Some(self.crypto.encrypt(self.buf[..l].as_ref()));
        }
    }
}

pub struct LogDedup {
    previous: Option<&'static str>,
    times: u32,
}

impl LogDedup {
    pub fn new() -> LogDedup {
        LogDedup {
            previous: None,
            times: 0,
        }
    }

    pub fn warn(&mut self, s: &'static str) {
        let p1 = match self.previous {
            None => {
                warn!("{}", s);
                s
            }
            Some(p) => {
                if p != s {
                    self.clear();
                    warn!("{}", s);
                    s
                } else {
                    self.times += 1;
                    p
                }
            }
        };
        self.previous = Some(p1);
    }

    fn clear(&mut self) {
        if self.previous.is_some() && self.times > 0 {
            warn!("Message \"{}\": repeated {} times.",
                  self.previous.unwrap(),
                  self.times);
            self.times = 0;
        }
    }
}

impl Drop for LogDedup {
    fn drop(&mut self) {
        self.clear();
    }
}
