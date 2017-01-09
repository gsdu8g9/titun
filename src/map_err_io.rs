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

use std::io::{Error, Result, ErrorKind};

pub trait MapErrIo<T> {
    fn map_err_io(self) -> Result<T>;
}

impl<T, E> MapErrIo<T> for ::std::result::Result<T, E>
    where E: Into<Box<::std::error::Error + Send + Sync>>
{
    fn map_err_io(self) -> Result<T> {
        self.map_err(|e| Error::new(ErrorKind::Other, e))
    }
}
