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

#![feature(test)]

extern crate sodiumoxide;
extern crate test;
extern crate titun;

use sodiumoxide::crypto::secretbox::{gen_key, gen_nonce, seal};
use test::Bencher;
use titun::crypto::*;

#[bench]
fn bench_encryption(b: &mut Bencher) {
    sodiumoxide::init();
    let k = gen_key();
    let msg = [0u8; 1400];
    let cr = Crypto::new(k, DEFAULT_MAX_DIFF);
    b.bytes = 1400;
    b.iter(|| cr.encrypt(&msg));
}

#[bench]
fn bench_ecryption_bare(b: &mut Bencher) {
    sodiumoxide::init();
    let k = gen_key();
    let msg = [0u8; 1400];
    let mut n = gen_nonce();
    b.bytes = 1400;
    b.iter(|| {
        n.increment_le_inplace();
        seal(&msg, &n, &k)
    });
}
