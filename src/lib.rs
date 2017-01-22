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

extern crate byteorder;
extern crate data_encoding;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate mio;
extern crate nix;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate sodiumoxide;
extern crate test;
#[macro_use]
extern crate tokio_core;
extern crate tokio_signal;

pub mod config;
pub mod crypto;
pub mod map_err_io;
pub mod script_runner;
pub mod systemd_notify;
pub mod titun;
pub mod tun;
