// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::config::Config;
use crate::context::Context;
use crate::core;
use crate::encoding;
use crate::memory::Memory;
use crate::result::Result;
use crate::thread_mode::ThreadMode;
use crate::variant::Variant;
use crate::version::Version;

use constant_time_eq::constant_time_eq;

/// Returns the length of the encoded string.
///
/// # Remarks
///
/// The length is **one** less that the original C version, since no null
/// terminator is used.
///
/// # Examples
///
/// ```rust
/// use argon2::{self, Variant};
///
/// let variant = Variant::Argon2i;
/// let mem = 4096;
/// let time = 10;
/// let parallelism = 10;
/// let salt_len = 8;
/// let hash_len = 32;
/// let enc_len = argon2::encoded_len(variant, mem, time, parallelism, salt_len, hash_len);
/// assert_eq!(enc_len, 86);
/// ```
#[rustfmt::skip]
pub fn encoded_len(
    variant: Variant,
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
    salt_len: u32,
    hash_len: u32
) -> u32 {
    ("$$v=$m=,t=,p=$$".len() as u32)  +
    (variant.as_lowercase_str().len() as u32) +
    encoding::num_len(Version::default().as_u32()) +
    encoding::num_len(mem_cost) +
    encoding::num_len(time_cost) +
    encoding::num_len(parallelism) +
    encoding::base64_len(salt_len) +
    encoding::base64_len(hash_len)
}

/// Hashes the password and returns the encoded hash.
///
/// # Examples
///
/// Create an encoded hash with the default configuration:
///
/// ```
/// use argon2::{self, Config};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let config = Config::default();
/// let encoded = argon2::hash_encoded(pwd, salt, &config).unwrap();
/// ```
///
///
/// Create an Argon2d encoded hash with 4 lanes and parallel execution:
///
/// ```
/// use argon2::{self, Config, ThreadMode, Variant};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let mut config = Config::default();
/// config.variant = Variant::Argon2d;
#[cfg_attr(feature = "crossbeam-utils", doc = "config.lanes = 4;")]
#[cfg_attr(
    feature = "crossbeam-utils",
    doc = "config.thread_mode = ThreadMode::Parallel;"
)]
#[cfg_attr(not(feature = "crossbeam-utils"), doc = "config.lanes = 1;")]
#[cfg_attr(
    not(feature = "crossbeam-utils"),
    doc = "config.thread_mode = ThreadMode::Sequential;"
)]
/// let encoded = argon2::hash_encoded(pwd, salt, &config).unwrap();
/// ```
pub fn hash_encoded(pwd: &[u8], salt: &[u8], config: &Config) -> Result<String> {
    let context = Context::new(config.clone(), pwd, salt)?;
    let hash = run(&context);
    let encoded = encoding::encode_string(&context, &hash);
    Ok(encoded)
}

/// Hashes the password and returns the hash as a vector.
///
/// # Examples
///
/// Create a hash with the default configuration:
///
/// ```
/// use argon2::{self, Config};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let config = Config::default();
/// let vec = argon2::hash_raw(pwd, salt, &config).unwrap();
/// ```
///
///
/// Create an Argon2d hash with 4 lanes and parallel execution:
///
/// ```
/// use argon2::{self, Config, ThreadMode, Variant};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let mut config = Config::default();
/// config.variant = Variant::Argon2d;
#[cfg_attr(feature = "crossbeam-utils", doc = "config.lanes = 4;")]
#[cfg_attr(
    feature = "crossbeam-utils",
    doc = "config.thread_mode = ThreadMode::Parallel;"
)]
#[cfg_attr(not(feature = "crossbeam-utils"), doc = "config.lanes = 1;")]
#[cfg_attr(
    not(feature = "crossbeam-utils"),
    doc = "config.thread_mode = ThreadMode::Sequential;"
)]
/// let vec = argon2::hash_raw(pwd, salt, &config).unwrap();
/// ```
pub fn hash_raw(pwd: &[u8], salt: &[u8], config: &Config) -> Result<Vec<u8>> {
    let context = Context::new(config.clone(), pwd, salt)?;
    let hash = run(&context);
    Ok(hash)
}

/// Verifies the password with the encoded hash.
///
/// # Examples
///
/// ```
/// use argon2;
///
/// let enc = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ\
///            $iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A";
/// let pwd = b"password";
/// let res = argon2::verify_encoded(enc, pwd).unwrap();
/// assert!(res);
/// ```
pub fn verify_encoded(encoded: &str, pwd: &[u8]) -> Result<bool> {
    verify_encoded_ext(encoded, pwd, &[], &[])
}

/// Verifies the password with the encoded hash, secret and associated data.
///
/// # Examples
///
/// ```
/// use argon2;
///
/// let enc = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ\
///            $OlcSvlN20Lz43sK3jhCJ9K04oejhiY0AmI+ck6nuETo";
/// let pwd = b"password";
/// let secret = b"secret";
/// let ad = b"ad";
/// let res = argon2::verify_encoded_ext(enc, pwd, secret, ad).unwrap();
/// assert!(res);
/// ```
pub fn verify_encoded_ext(encoded: &str, pwd: &[u8], secret: &[u8], ad: &[u8]) -> Result<bool> {
    let decoded = encoding::decode_string(encoded)?;
    let threads = if cfg!(feature = "crossbeam-utils") {
        decoded.parallelism
    } else {
        1
    };
    let config = Config {
        variant: decoded.variant,
        version: decoded.version,
        mem_cost: decoded.mem_cost,
        time_cost: decoded.time_cost,
        lanes: decoded.parallelism,
        thread_mode: ThreadMode::from_threads(threads),
        secret,
        ad,
        hash_length: decoded.hash.len() as u32,
    };
    verify_raw(pwd, &decoded.salt, &decoded.hash, &config)
}

/// Verifies the password with the supplied configuration.
///
/// # Examples
///
/// ```
/// use argon2::{self, Config};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let hash = &[158, 135, 137, 200, 180, 40, 52, 34, 10, 252, 0, 8, 90, 199,
///              58, 204, 48, 134, 81, 33, 105, 148, 171, 191, 221, 214, 155,
///              37, 146, 3, 46, 253];
/// let config = Config::rfc9106_low_mem();
/// let res = argon2::verify_raw(pwd, salt, hash, &config).unwrap();
/// assert!(res);
/// ```
pub fn verify_raw(pwd: &[u8], salt: &[u8], hash: &[u8], config: &Config) -> Result<bool> {
    let config = Config {
        hash_length: hash.len() as u32,
        ..config.clone()
    };
    let context = Context::new(config, pwd, salt)?;
    let calculated_hash = run(&context);
    Ok(constant_time_eq(hash, &calculated_hash))
}

fn run(context: &Context) -> Vec<u8> {
    let mut memory = Memory::new(context.config.lanes, context.lane_length);
    core::initialize(context, &mut memory);
    // SAFETY: `memory` is constructed from `context`.
    unsafe { core::fill_memory_blocks(context, &mut memory) };
    core::finalize(context, &memory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_thread_verification_multi_lane_hash() {
        let hash = "$argon2i$v=19$m=4096,t=3,p=4$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo$\
                    BvBk2OaSofBHfbrUW61nHrWB/43xgfs/QJJ5DkMAd8I";
        let res = verify_encoded(hash, b"foo").unwrap();
        assert!(res);
    }

    #[test]
    fn test_argon2id_for_miri() {
        let hash = "$argon2id$v=19$m=256,t=2,p=16$c29tZXNhbHQ$\
                    0gasyPnKXiBHQ5bft/bd4jrmy2DdtrLTX3JR9co7fRY";
        let res = verify_encoded(hash, b"password").unwrap();
        assert!(res);
    }

    #[test]
    fn test_argon2id_for_miri_2() {
        let hash = "$argon2id$v=19$m=512,t=2,p=8$c29tZXNhbHQ$\
                    qgW4yz2jO7oklapDpVwzUYgfDLzfwkppGTvhRDDBjkY";
        let res = verify_encoded(hash, b"password").unwrap();
        assert!(res);
    }

    #[test]
    fn test_argon2d_for_miri() {
        let hash = "$argon2d$v=19$m=256,t=2,p=16$c29tZXNhbHQ$\
                    doW5kZ/0cTwqwbYTwr9JD0wNwy3tMyJMMk9ojGsC8bk";
        let res = verify_encoded(hash, b"password").unwrap();
        assert!(res);
    }

    #[test]
    fn test_argon2i_for_miri() {
        let hash = "$argon2i$v=19$m=256,t=2,p=16$c29tZXNhbHQ$\
                    c1suSp12ZBNLSuyhD8pJriM2r5jP2kgZ5QdDAk3+HaY";
        let res = verify_encoded(hash, b"password").unwrap();
        assert!(res);
    }
}
