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
use error::Result;
use script_runner::ScriptRunner;
use std::net::UdpSocket;
use std::sync::Arc;
use systemd;
use tun::Tun;
use wireguard::*;

// TODO determine number of threads based on number of CPU threads.
// TODO: SO_REUSEPORT.
// TODO: Multiqueue TUN.

const NUM_UDP_THREADS: usize = 1;
// Get 100% CPU usage with more than one thread reading from the
// same TUN dev, on a box with 4.8 kernel. Use 1 thread for now.
const NUM_TUN_THREADS: usize = 1;

pub fn run(c: Config) -> Result<()> {
    let wg = WgState::new(c.info, &c.peers);
    let bind_addr = if c.listen_port.is_none() {
        "[::]:0".to_string()
    } else {
        format!("[::]:{}", c.listen_port.unwrap())
    };
    let sock = Arc::new(UdpSocket::bind(bind_addr)?);
    let tun = Arc::new(Tun::create(Some(&c.dev_name))?);

    c.on_up.map(|s| ScriptRunner::new().run(s.as_bytes()));
    systemd::notify_ready();

    let mut handles = Vec::with_capacity(NUM_TUN_THREADS + NUM_UDP_THREADS + 1);

    for _ in 0..NUM_UDP_THREADS {
        handles.push(start_udp_recv(wg.clone(), sock.clone(), tun.clone()));
    }
    for _ in 0..NUM_TUN_THREADS {
        handles.push(start_packet_read(wg.clone(), sock.clone(), tun.clone()));
    }
    handles.push(start_maintaining_thread(wg, sock));

    // TODO ensure that these threads are still running.
    // TODO graceful exit.
    // TODO run `on_down` script.
    for h in handles {
        h.join().unwrap()
    }

    Ok(())
}
