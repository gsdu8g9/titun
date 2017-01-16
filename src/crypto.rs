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

//! Use time based nonce with `crypto_secretbox`.
//!
//! The first 8 bytes of nonce is number of nanoseconds since UNIX epoch, in big-endian. The rest
//! is randomly generated. Nonce is appended to ciphertext.

// TODO forward secrecy???

use byteorder::{BigEndian, ByteOrder};
use sodiumoxide::crypto::secretbox::{Key, NONCEBYTES, Nonce, open, seal};
use sodiumoxide::randombytes::randombytes_into;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_DIFF: u64 = 3000000000;

pub struct Crypto {
    key: Key,
    last_time: u64,
    rand_bytes: [u8; 16],
    max_diff: u64,
}

impl Crypto {
    pub fn new(k: Key, max_diff: u64) -> Crypto {
        let t = system_time_to_nanos_epoch(SystemTime::now());
        let mut r = [0u8; 16];
        randombytes_into(&mut r[..]);
        Crypto {
            key: k,
            last_time: t,
            rand_bytes: r,
            max_diff: max_diff,
        }
    }

    // Reuse random part of nonce as long as time is later than last.
    fn get_nonce(&mut self) -> Nonce {
        let mut n = [0u8; 24];
        let t1 = system_time_to_nanos_epoch(SystemTime::now());
        BigEndian::write_u64(&mut n[..8], t1);
        if t1 > self.last_time {
            n[8..].copy_from_slice(&self.rand_bytes);
        } else {
            warn!("timestamp not increased");
            randombytes_into(&mut n[8..]);
            self.rand_bytes.copy_from_slice(&n[8..]);
        }
        self.last_time = t1;
        Nonce(n)
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let nonce = self.get_nonce();
        let mut e = seal(msg, &nonce, &self.key);
        e.extend_from_slice(nonce.as_ref());
        e
    }

    pub fn decrypt(&self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < NONCEBYTES {
            None
        } else {
            let (c, n) = msg.split_at(msg.len() - NONCEBYTES);
            let nonce = Nonce::from_slice(n).unwrap();
            if nonce_time_in_range(&nonce, self.max_diff) {
                open(c, &nonce, &self.key).ok()
            } else {
                None
            }
        }
    }
}

fn system_time_to_nanos_epoch(t: SystemTime) -> u64 {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    (d * 1000000000).as_secs()
}

fn nonce_time_in_range(n: &Nonce, max_diff: u64) -> bool {
    let m = BigEndian::read_u64(&n.0[..8]);
    let m1 = system_time_to_nanos_epoch(SystemTime::now());

    let d = if m1 > m { m1 - m } else { m - m1 };

    d <= max_diff
}

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::secretbox::{gen_key, gen_nonce};
    use std::thread::sleep;
    use std::time::Duration;
    use super::*;
    use test::Bencher;

    #[test]
    fn encryption_and_decryption() {
        let k = gen_key();
        let mut cr = Crypto::new(k, DEFAULT_MAX_DIFF);

        let c = cr.encrypt(&[2, 0, 1, 7]);
        let p = cr.decrypt(c.as_slice());

        assert_eq!(p.unwrap().as_ref(), [2, 0, 1, 7]);
        assert_eq!(cr.decrypt(&[3, 4, 8, 1]), None);

        sleep(Duration::from_secs(4));
        assert!(cr.decrypt(c.as_slice()).is_none());
    }

    #[bench]
    fn bench_encryption(b: &mut Bencher) {
        ::sodiumoxide::init();
        let k = gen_key();
        let msg = [0u8; 1400];
        let mut cr = Crypto::new(k, DEFAULT_MAX_DIFF);
        b.bytes = 1400;
        b.iter(|| cr.encrypt(&msg));
    }

    #[bench]
    fn bench_ecryption_bare(b: &mut Bencher) {
        ::sodiumoxide::init();
        let k = gen_key();
        let msg = [0u8; 1400];
        let mut n = gen_nonce();
        b.bytes = 1400;
        b.iter(|| {
            n.increment_le_inplace();
            seal(&msg, &n, &k)
        });
    }
}
