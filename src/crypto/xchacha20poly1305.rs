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

extern crate sodiumoxide;

use self::sodiumoxide::crypto::aead::chacha20poly1305::{self, Key, Nonce};
use super::hchacha20::hchacha20;

pub fn encrypt(key: &[u8], nonce: &[u8], ad: &[u8], p: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);

    let derived_key = hchacha20(&nonce[..16], key);
    let derived_key = Key(derived_key);

    let mut nonce1 = [0u8; 12];
    nonce1[4..].copy_from_slice(&nonce[16..]);
    let nonce1 = Nonce(nonce1);

    chacha20poly1305::encrypt(p, ad, &nonce1, &derived_key)
}

pub fn decrypt(key: &[u8], nonce: &[u8], ad: &[u8], c: &[u8]) -> Result<Vec<u8>, ()> {
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);

    let derived_key = hchacha20(&nonce[..16], key);
    let derived_key = Key(derived_key);

    let mut nonce1 = [0u8; 12];
    nonce1[4..].copy_from_slice(&nonce[16..]);
    let nonce1 = Nonce(nonce1);

    chacha20poly1305::decrypt(c, ad, &nonce1, &derived_key)
}
