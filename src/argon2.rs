// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::context::Context;
use super::common;
use super::core;
use super::encoding;
use super::memory::Memory;
use super::result::Result;
use super::thread_mode::ThreadMode;
use super::variant::Variant;
use super::version::Version;

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
#[cfg_attr(rustfmt, rustfmt_skip)]
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
///
/// ```
/// use argon2::{self, ThreadMode, Variant, Version};
///
/// let mem_cost = 4096;
/// let time_cost = 10;
/// let lanes = 1;
/// let thread_mode = ThreadMode::Sequential;
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let secret = b"secret value";
/// let ad = b"associated data";
/// let hash_len = 32;
/// let encoded = argon2::hash_encoded(Variant::Argon2i,
///                                    Version::Version13,
///                                    mem_cost,
///                                    time_cost,
///                                    lanes,
///                                    thread_mode,
///                                    pwd,
///                                    salt,
///                                    secret,
///                                    ad,
///                                    hash_len).unwrap();
/// ```
pub fn hash_encoded(
    variant: Variant,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
    thread_mode: ThreadMode,
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    hash_len: u32
) -> Result<String> {
    let context = try!(Context::new(variant,
                                    version,
                                    mem_cost,
                                    time_cost,
                                    lanes,
                                    thread_mode,
                                    pwd,
                                    salt,
                                    secret,
                                    ad,
                                    hash_len));
    let hash = run(&context);
    let encoded = encoding::encode_string(&context, &hash);
    Ok(encoded)
}

/// Hashes the password using default settings and returns the encoded hash.
///
/// # Examples
///
///
/// ```
/// use argon2;
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let encoded = argon2::hash_encoded_defaults(pwd, salt).unwrap();
/// ```
///
/// # Remarks
///
/// The following settings are used:
///
/// - variant: Variant::Argon2i
/// - version: Version::Version13
/// - mem_cost: 4096
/// - time_cost: 3
/// - lanes: 1
/// - thread_mode: sequential
/// - secret: empty slice
/// - ad: empty slice
/// - hash_len: 32
pub fn hash_encoded_defaults(pwd: &[u8], salt: &[u8]) -> Result<String> {
    hash_encoded(Variant::default(),
                 Version::default(),
                 common::DEF_MEMORY,
                 common::DEF_TIME,
                 common::DEF_LANES,
                 ThreadMode::default(),
                 pwd,
                 salt,
                 &[],
                 &[],
                 common::DEF_HASH_LENGTH)
}

/// Hashes the password and returns the encoded hash (standard).
///
/// # Examples
///
///
/// ```
/// use argon2::{self, Variant, Version};
///
/// let mem_cost = 4096;
/// let time_cost = 10;
/// let parallelism = 1;
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let hash_len = 32;
/// let encoded = argon2::hash_encoded_std(Variant::Argon2i,
///                                        Version::Version13,
///                                        mem_cost,
///                                        time_cost,
///                                        parallelism,
///                                        pwd,
///                                        salt,
///                                        hash_len).unwrap();
/// ```
///
/// # Remarks
///
/// The following settings are used:
///
/// - lanes: parallelism
/// - thread_mode: sequential
/// - secret: empty slice
/// - ad: empty slice
/// ```
pub fn hash_encoded_std(
    variant: Variant,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
    pwd: &[u8],
    salt: &[u8],
    hash_len: u32
) -> Result<String> {
    hash_encoded(variant,
                 version,
                 mem_cost,
                 time_cost,
                 parallelism,
                 ThreadMode::Sequential,
                 pwd,
                 salt,
                 &[],
                 &[],
                 hash_len)
}


/// Hashes the password and returns the hash as a vector.
///
/// # Examples
///
///
/// ```
/// use argon2::{self, ThreadMode, Variant, Version};
///
/// let mem_cost = 4096;
/// let time_cost = 10;
/// let lanes = 1;
/// let thread_mode = ThreadMode::Sequential;
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let secret = b"secret value";
/// let ad = b"associated data";
/// let hash_len = 32;
/// let vec = argon2::hash_raw(Variant::Argon2i,
///                            Version::Version13,
///                            mem_cost,
///                            time_cost,
///                            lanes,
///                            thread_mode,
///                            pwd,
///                            salt,
///                            secret,
///                            ad,
///                            hash_len).unwrap();
/// ```
pub fn hash_raw(
    variant: Variant,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
    thread_mode: ThreadMode,
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    hash_len: u32
) -> Result<Vec<u8>> {
    let context = try!(Context::new(variant,
                                    version,
                                    mem_cost,
                                    time_cost,
                                    lanes,
                                    thread_mode,
                                    pwd,
                                    salt,
                                    secret,
                                    ad,
                                    hash_len));
    let hash = run(&context);
    Ok(hash)
}


/// Hashes the password using default settings and returns the hash as a vector.
///
/// # Examples
///
///
/// ```
/// use argon2;
///
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let vec = argon2::hash_raw_defaults(pwd, salt).unwrap();
/// ```
///
/// # Remarks
///
/// The following settings are used:
///
/// - variant: Variant::Argon2i
/// - version: Version::Version13
/// - mem_cost: 4096
/// - time_cost: 3
/// - lanes: 1
/// - thread_mode: sequential
/// - secret: empty slice
/// - ad: empty slice
/// - hash_len: 32
pub fn hash_raw_defaults(pwd: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    hash_raw(Variant::default(),
             Version::default(),
             common::DEF_MEMORY,
             common::DEF_TIME,
             common::DEF_LANES,
             ThreadMode::default(),
             pwd,
             salt,
             &[],
             &[],
             common::DEF_HASH_LENGTH)
}


/// Hashes the password and returns the hash as a vector (standard).
///
/// # Examples
///
///
/// ```
/// use argon2::{self, Variant, Version};
///
/// let mem_cost = 4096;
/// let time_cost = 10;
/// let parallelism = 1;
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let hash_len = 32;
/// let vec = argon2::hash_raw_std(Variant::Argon2i,
///                                Version::Version13,
///                                mem_cost,
///                                time_cost,
///                                parallelism,
///                                pwd,
///                                salt,
///                                hash_len).unwrap();
/// ```
///
/// # Remarks
///
/// The following settings are used:
///
/// - lanes: parallelism
/// - thread_mode: sequential
/// - secret: empty slice
/// - ad: empty slice
/// ```
pub fn hash_raw_std(
    variant: Variant,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
    pwd: &[u8],
    salt: &[u8],
    hash_len: u32
) -> Result<Vec<u8>> {
    hash_raw(variant,
             version,
             mem_cost,
             time_cost,
             parallelism,
             ThreadMode::Sequential,
             pwd,
             salt,
             &[],
             &[],
             hash_len)
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
    let decoded = try!(encoding::decode_string(encoded));
    verify_raw(decoded.variant,
               decoded.version,
               decoded.mem_cost,
               decoded.time_cost,
               decoded.parallelism,
               ThreadMode::Parallel,
               pwd,
               &decoded.salt,
               &[],
               &[],
               &decoded.hash)
}

/// Verifies the password with the supplied settings.
///
/// # Examples
///
///
/// ```
/// use argon2::{self, ThreadMode, Variant, Version};
///
/// let mem_cost = 4096;
/// let time_cost = 3;
/// let lanes = 1;
/// let thread_mode = ThreadMode::Sequential;
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let secret = &[];
/// let ad = &[];
/// let hash = &[137, 104, 116, 234, 240, 252, 23, 45, 187, 193, 255, 103, 166,
///              126, 133, 93, 104, 130, 95, 130, 186, 165, 110, 148, 123, 80,
///              103, 207, 61, 59, 103, 192];
/// let res = argon2::verify_raw(Variant::Argon2i,
///                              Version::Version13,
///                              mem_cost,
///                              time_cost,
///                              lanes,
///                              thread_mode,
///                              pwd,
///                              salt,
///                              secret,
///                              ad,
///                              hash).unwrap();
/// assert!(res);
/// ```
pub fn verify_raw(
    variant: Variant,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
    thread_mode: ThreadMode,
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    hash: &[u8]
) -> Result<bool> {
    let context = try!(Context::new(variant,
                                    version,
                                    mem_cost,
                                    time_cost,
                                    lanes,
                                    thread_mode,
                                    pwd,
                                    salt,
                                    secret,
                                    ad,
                                    hash.len() as u32));
    Ok(run(&context) == hash)
}


/// Verifies the password with the supplied settings (standard).
///
/// # Examples
///
///
/// ```
/// use argon2::{self, Variant, Version};
///
/// let mem_cost = 4096;
/// let time_cost = 3;
/// let parallelism = 1;
/// let pwd = b"password";
/// let salt = b"somesalt";
/// let hash = &[137, 104, 116, 234, 240, 252, 23, 45, 187, 193, 255, 103, 166,
///              126, 133, 93, 104, 130, 95, 130, 186, 165, 110, 148, 123, 80,
///              103, 207, 61, 59, 103, 192];
/// let res = argon2::verify_raw_std(Variant::Argon2i,
///                                  Version::Version13,
///                                  mem_cost,
///                                  time_cost,
///                                  parallelism,
///                                  pwd,
///                                  salt,
///                                  hash).unwrap();
/// assert!(res);
/// ```
pub fn verify_raw_std(
    variant: Variant,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
    pwd: &[u8],
    salt: &[u8],
    hash: &[u8]
) -> Result<bool> {
    verify_raw(variant,
               version,
               mem_cost,
               time_cost,
               parallelism,
               ThreadMode::Parallel,
               pwd,
               salt,
               &[],
               &[],
               hash)
}

fn run(context: &Context) -> Vec<u8> {
    let mut memory = Memory::new(context.lanes, context.lane_length);
    core::initialize(context, &mut memory);
    core::fill_memory_blocks(context, &mut memory);
    core::finalize(context, &memory)
}
