// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::variant::Variant;
use crate::version::Version;

/// Structure containing configuration settings.
///
/// # Examples
///
/// ```
/// use argon2::{Config, Variant, Version};
///
/// let config = Config::default();
/// assert_eq!(config.ad, &[]);
/// assert_eq!(config.hash_length, 32);
/// assert_eq!(config.lanes, 1);
/// assert_eq!(config.mem_cost, 2 * 1024 * 1024);
/// assert_eq!(config.secret, &[]);
/// assert_eq!(config.time_cost, 1);
/// assert_eq!(config.variant, Variant::Argon2id);
/// assert_eq!(config.version, Version::Version13);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Config<'a> {
    /// The associated data.
    pub ad: &'a [u8],

    /// The length of the resulting hash.
    pub hash_length: u32,

    /// The number of lanes.
    pub lanes: u32,

    /// The amount of memory requested (KB).
    pub mem_cost: u32,

    /// The key.
    pub secret: &'a [u8],

    /// The number of passes.
    pub time_cost: u32,

    /// The variant.
    pub variant: Variant,

    /// The version number.
    pub version: Version,
}

impl<'a> Config<'a> {
    /// Default configuration used by the original C implementation.
    pub fn original() -> Config<'a> {
        Config {
            ad: &[],
            hash_length: 32,
            lanes: 1,
            mem_cost: 4096,
            secret: &[],
            time_cost: 3,
            variant: Variant::Argon2i,
            version: Version::Version13,
        }
    }

    /// RFC9106 recommended configuration with t=1 and 2 GiB memory.
    pub fn rfc9106() -> Config<'a> {
        Config {
            ad: &[],
            hash_length: 32,
            lanes: 1,
            mem_cost: 2097152,
            secret: &[],
            time_cost: 1,
            variant: Variant::Argon2id,
            version: Version::Version13,
        }
    }

    /// RFC9106 recommended configuration for memory-constrained environments.
    pub fn rfc9106_low_mem() -> Config<'a> {
        Config {
            ad: &[],
            hash_length: 32,
            lanes: 1,
            mem_cost: 65536,
            secret: &[],
            time_cost: 3,
            variant: Variant::Argon2id,
            version: Version::Version13,
        }
    }
}

impl<'a> Default for Config<'a> {
    /// RFC9106 recommended configuration with t=1 and 2 GiB memory.
    fn default() -> Config<'a> {
        Config::rfc9106()
    }
}

#[cfg(test)]
mod tests {

    use crate::config::Config;
    use crate::variant::Variant;
    use crate::version::Version;

    #[test]
    fn default_returns_correct_instance() {
        let config = Config::default();
        assert_eq!(config.ad, &[]);
        assert_eq!(config.hash_length, 32);
        assert_eq!(config.lanes, 1);
        assert_eq!(config.mem_cost, 2 * 1024 * 1024);
        assert_eq!(config.secret, &[]);
        assert_eq!(config.time_cost, 1);
        assert_eq!(config.variant, Variant::Argon2id);
        assert_eq!(config.version, Version::Version13);
    }

    #[test]
    fn original_returns_correct_instance() {
        let config = Config::original();
        assert_eq!(config.ad, &[]);
        assert_eq!(config.hash_length, 32);
        assert_eq!(config.lanes, 1);
        assert_eq!(config.mem_cost, 4096);
        assert_eq!(config.secret, &[]);
        assert_eq!(config.time_cost, 3);
        assert_eq!(config.variant, Variant::Argon2i);
        assert_eq!(config.version, Version::Version13);
    }

    #[test]
    fn rfc9106_returns_correct_instance() {
        let config = Config::rfc9106();
        assert_eq!(config.ad, &[]);
        assert_eq!(config.hash_length, 32);
        assert_eq!(config.lanes, 1);
        assert_eq!(config.mem_cost, 2 * 1024 * 1024);
        assert_eq!(config.secret, &[]);
        assert_eq!(config.time_cost, 1);
        assert_eq!(config.variant, Variant::Argon2id);
        assert_eq!(config.version, Version::Version13);
    }

    #[test]
    fn rfc9106_low_mem_returns_correct_instance() {
        let config = Config::rfc9106_low_mem();
        assert_eq!(config.ad, &[]);
        assert_eq!(config.hash_length, 32);
        assert_eq!(config.lanes, 1);
        assert_eq!(config.mem_cost, 64 * 1024);
        assert_eq!(config.secret, &[]);
        assert_eq!(config.time_cost, 3);
        assert_eq!(config.variant, Variant::Argon2id);
        assert_eq!(config.version, Version::Version13);
    }
}
