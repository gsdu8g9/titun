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

#!/bin/sh

# Need musl-gcc.

set -e

wget https://github.com/jedisct1/libsodium/releases/download/1.0.11/libsodium-1.0.11.tar.gz
tar xf libsodium-1.0.11.tar.gz
cd libsodium-1.0.11
CC=musl-gcc ./configure --disable-shared
make -j8

export SODIUM_LIB_DIR=$PWD/src/libsodium/.libs/
export SODIUM_STATIC=1

cargo build --release --target x86_64-unknown-linux-musl
