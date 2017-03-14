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

extern crate byteorder;
extern crate noise_protocol;
extern crate noise_sodiumoxide;

use self::byteorder::{ByteOrder, LittleEndian};
use self::noise_protocol::Cipher;
use self::noise_sodiumoxide::{ChaCha20Poly1305, SecretKey};
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::time::{Duration, Instant};
use wireguard::*;

struct RecvStatus {
    ar: AntiReplay,
    last: Option<Instant>,
}

/// A WireGuard transport session.
pub struct Transport {
    self_id: Id,
    peer_id: Id,
    // Whether the handshake is initiated by us.
    is_initiator: bool,
    created: Instant,
    send_key: SecretKey,
    recv_key: SecretKey,

    recv_status: Mutex<RecvStatus>,

    send_counter: AtomicU64,
    last_send: Mutex<Option<Instant>>,
}

impl Transport {
    pub fn new_from_hs(self_id: Id, peer_id: Id, hs: HS) -> Self {
        let (x, y) = hs.get_ciphers();
        let (s, r) = if hs.get_is_initiator() {
            (x, y)
        } else {
            (y, x)
        };
        let sk = s.extract().0;
        let rk = r.extract().0;

        Transport {
            self_id: self_id,
            peer_id: peer_id,
            is_initiator: hs.get_is_initiator(),
            send_key: sk,
            recv_key: rk,
            created: Instant::now(),
            recv_status: Mutex::new(RecvStatus {
                ar: AntiReplay::new(),
                last: None,
            }),
            send_counter: AtomicU64::new(0),
            last_send: Mutex::new(None),
        }
    }

    pub fn should_rekey(&self) -> bool {
        let last_send = self.last_send
            .lock()
            .unwrap()
            .clone();
        let last_recv = self.recv_status
            .lock()
            .unwrap()
            .last
            .clone();

        if last_send > last_recv &&
           last_send.unwrap() - last_recv.unwrap_or(self.created) >
           Duration::from_secs(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) {
            return true;
        }

        let rekey_time = REKEY_AFTER_TIME +
                         if self.is_initiator {
            0
        } else {
            2 * REKEY_TIMEOUT
        };
        let rekey_time = Duration::from_secs(rekey_time);

        self.created.elapsed() >= rekey_time ||
        self.send_counter.load(SeqCst) >= REKEY_AFTER_MESSAGES
    }

    pub fn should_keepalive(&self) -> bool {
        let last_send = self.last_send
            .lock()
            .unwrap()
            .clone();
        let last_recv = self.recv_status
            .lock()
            .unwrap()
            .last
            .clone();

        last_recv > last_send &&
        last_recv.unwrap() - last_send.unwrap_or(self.created) >=
        Duration::from_secs(KEEPALIVE_TIMEOUT)
    }

    pub fn should_delete(&self) -> bool {
        self.created.elapsed() >= Duration::from_secs(REJECT_AFTER_TIME * 3)
    }

    pub fn get_self_id(&self) -> Id {
        self.self_id
    }

    /// Expect packet with padding.
    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, ()> {
        let c = self.send_counter.fetch_add(1, Relaxed);
        if c >= REJECT_AFTER_MESSAGES {
            // To avoid overflow wrapping.
            self.send_counter.store(REJECT_AFTER_MESSAGES, SeqCst);
            return Err(());
        }

        let mut out = vec![0u8; msg.len() + 32];
        out[0..4].copy_from_slice(&[4, 0, 0, 0]);
        out[4..8].copy_from_slice(self.peer_id.as_slice());
        LittleEndian::write_u64(&mut out[8..16], c);

        <ChaCha20Poly1305 as Cipher>::encrypt(&self.send_key, c, &[], msg, &mut out[16..]);

        *self.last_send.lock().unwrap() = Some(Instant::now());

        Ok(out)
    }

    /// Returns packet maybe with padding.
    pub fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>, ()> {
        if msg.len() < 32 {
            return Err(());
        }

        if msg[0..4] != [4, 0, 0, 0] {
            return Err(());
        }

        if self.created.elapsed() >= Duration::from_secs(REJECT_AFTER_TIME) {
            return Err(());
        }

        let counter = LittleEndian::read_u64(&msg[8..16]);

        if counter >= REJECT_AFTER_MESSAGES {
            return Err(());
        }

        let mut out = vec![0u8; msg.len() - 32];
        <ChaCha20Poly1305 as Cipher>::decrypt(&self.recv_key, counter, &[], &msg[16..], &mut out)?;

        let mut status = self.recv_status.lock().unwrap();

        if !status.ar.check_and_update(counter) {
            return Err(());
        }

        status.last = Some(Instant::now());
        Ok(out)
    }
}
