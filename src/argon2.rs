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
/// Create an Argon2d encoded hash with 4 lanes:
///
/// ```
/// use argon2::{self, Config, Variant};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let mut config = Config::default();
/// config.variant = Variant::Argon2d;
/// config.lanes = 4;
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
/// Create an Argon2d hash with 4 lanes:
///
/// ```
/// use argon2::{self, Config, Variant};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let mut config = Config::default();
/// config.variant = Variant::Argon2d;
/// config.lanes = 4;
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
    let config = Config {
        variant: decoded.variant,
        version: decoded.version,
        mem_cost: decoded.mem_cost,
        time_cost: decoded.time_cost,
        lanes: decoded.parallelism,
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
///
/// ```
/// use argon2::{self, Config};
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let hash = &[137, 104, 116, 234, 240, 252, 23, 45, 187, 193, 255, 103, 166,
///              126, 133, 93, 104, 130, 95, 130, 186, 165, 110, 148, 123, 80,
///              103, 207, 61, 59, 103, 192];
/// let config = Config::default();
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
    core::fill_memory_blocks(context, &mut memory);
    core::finalize(context, &memory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_thread_verification_multi_lane_hash() {
        /*
        let hash = hash_encoded(b"foo", b"abcdefghijklmnopqrstuvwxyz", &Config {
            lanes: 4, thread_mode: ThreadMode::Parallel,
            ..Config::default()
        });
        */
        let hash = "$argon2i$v=19$m=4096,t=3,p=4$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo$BvBk2OaSofBHfbrUW61nHrWB/43xgfs/QJJ5DkMAd8I";
        verify_encoded(hash, b"foo").unwrap();
    }
}
