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

use crypto::DEFAULT_MAX_DIFF;
use data_encoding::base64;
use map_err_io::MapErrIo;
use serde_yaml as yaml;
use sodiumoxide::crypto::secretbox::{KEYBYTES, Key, gen_key};
use std::io::{Error, ErrorKind};

#[derive(Serialize, Deserialize)]
struct Config1 {
    pub bind: Option<String>,
    pub peer: Option<String>,
    pub key: String,
    pub config_script: Option<String>,
    pub bufsize: Option<usize>,
    pub max_diff: Option<u64>,
    pub dev_name: Option<String>,
}

/// One of bind / peer must be set.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub bind: Option<String>,
    pub peer: Option<String>,
    pub key: Key,
    pub config_script: Option<String>,
    pub bufsize: usize,
    pub max_diff: u64,
    pub dev_name: Option<String>,
}

impl Config {
    pub fn parse(s: &str) -> Result<Config, Error> {
        let v: yaml::Value = yaml::from_str(s).map_err_io()?;
        if let yaml::Value::Mapping(ref m) = v {
            for k in m.keys() {
                let k = k.as_str().unwrap();
                match k {
                    "bind" | "peer" | "key" | "config_script" | "bufsize" => {}
                    _ => warn!("unknown config {}", k),
                }
            }
        }
        let c: Config1 = yaml::from_value(v).map_err_io()?;
        let key = decode_key(&c.key)
            .ok_or_else(|| Error::new(ErrorKind::Other, "Config: Failed to decode key"))?;
        if c.peer.is_none() && c.bind.is_none() {
            return Err(Error::new(ErrorKind::Other,
                                  "Config: one of `bind` or `peer` must be specified"));
        }
        Ok(Config {
            bind: c.bind,
            peer: c.peer,
            key: key,
            config_script: c.config_script,
            bufsize: c.bufsize.unwrap_or(65536),
            max_diff: c.max_diff.unwrap_or(DEFAULT_MAX_DIFF),
            dev_name: c.dev_name,
        })
    }
}

pub fn decode_key(k: &str) -> Option<Key> {
    match base64::decode(k.as_bytes()) {
        Ok(ref k) if k.len() == KEYBYTES => Some(Key::from_slice(k.as_ref()).unwrap()),
        _ => None,
    }
}

pub fn genkey_base64() -> String {
    let k = gen_key();
    base64::encode(k.0.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key_works() {
        let k = genkey_base64();
        assert!(decode_key(&k).is_some());
        assert!(decode_key("not a valid key").is_none());
    }

    #[test]
    fn parse_config() {
        let c0 = Config {
            bind: None,
            peer: Some("127.0.0.1:3000".to_string()),
            key: decode_key("Q3bSSKKonSsSt09ShImoD6JXf4z+r2ngQaCk/FFKwF8=").unwrap(),
            config_script: None,
            bufsize: 65536,
            max_diff: ::crypto::DEFAULT_MAX_DIFF,
            dev_name: None,
        };
        let c = Config::parse(r#"---
peer: "127.0.0.1:3000"
key: "Q3bSSKKonSsSt09ShImoD6JXf4z+r2ngQaCk/FFKwF8="
"#);
        assert_eq!(c.unwrap(), c0);
    }
}
