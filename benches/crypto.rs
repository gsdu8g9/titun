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
