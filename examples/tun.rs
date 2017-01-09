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


// This program tries to open a tun device, bring it up, ping the peer
// and read packets from it.

// Need to run with root.

// Expected output:

// PING 192.0.2.7 (192.0.2.7) 56(84) bytes of data.
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// Got packet: 84 bytes
// ...

extern crate futures;
extern crate tokio_core;
extern crate titun;

use futures::Future;
use std::io::Result;
use std::process::{Command, Child};
use tokio_core::reactor::{Core, PollEvented};
use titun::futures_more::repeat;
use titun::tun::Tun;

fn up_and_ping(name: &str) -> Result<Child> {
    Command::new("ip").args(&["link", "set", name, "up"]).output()?;
    // The network 192.0.2.0/24 is TEST-NET, suitable for use in
    // documentation and examples.
    Command::new("ip").args(&["addr", "add", "192.0.2.8", "peer", "192.0.2.7", "dev", name])
        .output()?;
    Command::new("ping").arg("192.0.2.7").spawn()
}

fn inner() -> Result<()> {
    let t = Tun::create(Some("tun-test-0"))?;
    t.set_nonblocking(true)?;

    up_and_ping(t.get_name())?;

    let mut core = Core::new()?;
    let handle = core.handle();

    let tun = PollEvented::new(t, &handle)?;
    let mut buf = [0u8; 2048];

    let fut = repeat(|buf| {
                         tokio_core::io::read(&tun, buf).map(|(_, buf, l)| {
                             println!("read {} bytes", l);
                             buf
                         })
                     },
                     buf.as_mut());

    core.run(fut)
}

fn main() {
    inner().unwrap_or_else(|e| {
        println!("Error: {}", e);
        ()
    })
}
