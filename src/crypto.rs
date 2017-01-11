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
//! The first 8 bytes of nonce is number of milliseconds since UNIX epoch, in big-endian. The rest
//! is randomly generated. Nonce is appended to ciphertext.

// TODO forward secrecy???

use byteorder::{BigEndian, ByteOrder};
use sodiumoxide::crypto::secretbox::{Key, NONCEBYTES, Nonce, open, seal};
use sodiumoxide::randombytes::randombytes_into;
use std::time::{SystemTime, UNIX_EPOCH};

// Max difference of timestamp in milliseconds: 3 seconds.
// TODO allow configuration of MAX_DIFF
const MAX_DIFF: u64 = 3000;

pub fn encrypt(key: &Key, msg: &[u8]) -> Vec<u8> {
    let nonce = gen_time_nonce();
    let mut e = seal(msg, &nonce, key);
    e.extend_from_slice(nonce.as_ref());
    e
}

pub fn decrypt(key: &Key, msg: &[u8]) -> Option<Vec<u8>> {
    if msg.len() < NONCEBYTES {
        None
    } else {
        let (c, n) = msg.split_at(msg.len() - NONCEBYTES);
        let nonce = Nonce::from_slice(n).unwrap();
        if nonce_time_in_range(&nonce, MAX_DIFF) {
            open(c, &nonce, key).ok()
        } else {
            None
        }
    }
}

fn system_time_to_millis_epoch(t: SystemTime) -> u64 {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    (d * 1000).as_secs()
}

fn gen_time_nonce() -> Nonce {
    let m = system_time_to_millis_epoch(SystemTime::now());
    let mut out = [0; NONCEBYTES];

    BigEndian::write_u64(&mut out[..8], m);

    randombytes_into(&mut out[8..NONCEBYTES]);

    Nonce(out)
}

fn nonce_time_in_range(n: &Nonce, max_diff: u64) -> bool {
    let m = BigEndian::read_u64(&n.0[..8]);
    let m1 = system_time_to_millis_epoch(SystemTime::now());

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
        let k = &gen_key();

        let c = encrypt(k, &[2, 0, 1, 7]);
        let p = decrypt(k, c.as_slice());

        assert_eq!(p.unwrap().as_ref(), [2, 0, 1, 7]);
        assert_eq!(decrypt(k, &[3, 4, 8, 1]), None);

        sleep(Duration::from_secs(4));
        assert!(decrypt(k, c.as_slice()).is_none());
    }

    #[test]
    fn nonce_time() {
        let n = gen_time_nonce();
        assert!(nonce_time_in_range(&n, 1000));
        sleep(Duration::from_secs(1));
        assert!(!nonce_time_in_range(&n, 500));
    }

    #[bench]
    fn bench_encryption(b: &mut Bencher) {
        ::sodiumoxide::init();
        let k = gen_key();
        let msg = [0u8; 1400];
        b.iter(|| encrypt(&k, &msg[..]));
    }

    #[bench]
    fn bench_ecryption_incr_nonce(b: &mut Bencher) {
        ::sodiumoxide::init();
        let k = gen_key();
        let msg = [0u8; 1400];
        let mut n = gen_nonce();
        b.iter(|| {
            n.increment_le_inplace();
            seal(&msg, &n, &k)
        });
    }
}
