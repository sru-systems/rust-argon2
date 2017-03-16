// Copyright (c) 2017 Xidorn Quan <me@upsuper.org>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// The thread mode used to perform the hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadMode {
    /// Run in one thread.
    Sequential,

    /// Run in the same number of threads as the number of lanes.
    Parallel,
}

impl Default for ThreadMode {
    fn default() -> ThreadMode {
        ThreadMode::Sequential
    }
}
