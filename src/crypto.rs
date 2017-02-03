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

use byteorder::{BigEndian, ByteOrder};
use sodiumoxide::crypto::secretbox::{Key, Nonce, open, seal};
use sodiumoxide::randombytes::randombytes_into;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_DIFF: u64 = 1000;

pub struct Crypto {
    key: Key,
    max_diff: u64,
}

impl Crypto {
    pub fn new(k: Key, max_diff: u64) -> Crypto {
        Crypto {
            key: k,
            max_diff: max_diff,
        }
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let mut n = [0u8; 24];
        randombytes_into(&mut n[8..]);
        let nonce = Nonce(n);

        let t = system_time_to_millis_epoch(SystemTime::now());
        let mut tt = [0u8; 8];
        BigEndian::write_u64(&mut tt, t);

        let mut m1 = msg.to_vec();
        // Does this need a reallocation?
        m1.extend_from_slice(&tt);

        let mut e = seal(m1.as_slice(), &nonce, &self.key);
        e.extend_from_slice(&n[8..]);
        e
    }

    pub fn decrypt(&self, msg: &[u8]) -> Option<Vec<u8>> {
        // 8 bytes timestamp, 16 bytes auth tag, 16 bytes random nonce.
        if msg.len() < 40 {
            None
        } else {
            let (c, n) = msg.split_at(msg.len() - 16);
            let mut nonce = Nonce([0; 24]);
            nonce.0[8..].copy_from_slice(n);
            open(c, &nonce, &self.key).ok().and_then(|mut m| {
                let len = m.len().checked_sub(8).unwrap();
                let t = BigEndian::read_u64(&m[len..]);
                let t0 = system_time_to_millis_epoch(SystemTime::now());
                let diff = if t > t0 { t - t0 } else { t0 - t };
                if diff <= self.max_diff {
                    m.truncate(len);
                    Some(m)
                } else {
                    None
                }
            })
        }
    }
}

fn system_time_to_millis_epoch(t: SystemTime) -> u64 {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    (d * 1000).as_secs()
}

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::secretbox::gen_key;
    use std::thread::sleep;
    use std::time::Duration;
    use super::*;

    #[test]
    fn encryption_and_decryption() {
        let k = gen_key();
        let cr = Crypto::new(k, DEFAULT_MAX_DIFF);

        let c = cr.encrypt(&[2, 0, 1, 7]);
        let p = cr.decrypt(c.as_slice());

        assert_eq!(p, Some(vec![2, 0, 1, 7]));
        assert_eq!(cr.decrypt(&[3, 4, 8, 1]), None);

        sleep(Duration::from_secs(2));
        assert!(cr.decrypt(c.as_slice()).is_none());

        let c1 = cr.encrypt(&[]);
        let p = cr.decrypt(c1.as_slice());

        assert_eq!(p, Some(vec![]));
    }
}
