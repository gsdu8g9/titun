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

//! Functions missing from `futures`?

use futures::{Future, IntoFuture, Poll};

/// Call a closure that returns a future repeatedly.
pub fn repeat<F, T, Fut>(mut f: F, t: T) -> Repeat<F, T, Fut>
    where F: FnMut(T) -> Fut,
          Fut: IntoFuture<Item = T>
{
    let fut = f(t).into_future();
    Repeat { f: f, fut: fut }
}

pub struct Repeat<F, T, Fut>
    where F: FnMut(T) -> Fut,
          Fut: IntoFuture<Item = T>
{
    f: F,
    fut: Fut::Future,
}

impl<F, T, Fut> Future for Repeat<F, T, Fut>
    where F: FnMut(T) -> Fut,
          Fut: IntoFuture<Item = T>
{
    type Item = ();
    type Error = Fut::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let t = try_ready!(self.fut.poll());
            self.fut = (self.f)(t).into_future();
        }
    }
}
