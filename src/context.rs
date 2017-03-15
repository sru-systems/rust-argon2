// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::common;
use super::error::Error;
use super::result::Result;
use super::thread_mode::ThreadMode;
use super::variant::Variant;
use super::version::Version;

/// Structure containing settings for the Argon2 algorithm. A combination of
/// the original argon2_context and argon2_instance_t.
#[derive(Debug, PartialEq)]
pub struct Context {
    /// The associated data.
    pub ad: Vec<u8>,

    /// The length of the resulting hash.
    pub hash_length: u32,

    /// The length of a lane.
    pub lane_length: u32,

    /// The number of lanes.
    pub lanes: u32,

    /// The amount of memory requested (KB).
    pub mem_cost: u32,

    /// The number of memory blocks.
    pub memory_blocks: u32,

    /// The password.
    pub pwd: Vec<u8>,

    /// The salt.
    pub salt: Vec<u8>,

    /// The key.
    pub secret: Vec<u8>,

    /// The length of a segment.
    pub segment_length: u32,

    /// The thread mode.
    pub thread_mode: ThreadMode,

    /// The number of passes.
    pub time_cost: u32,

    /// The variant.
    pub variant: Variant,

    /// The version number.
    pub version: Version,
}

impl Context {
    /// Attempts to create a new context.
    pub fn new(
        variant: Variant,
        version: Version,
        mem_cost: u32,
        time_cost: u32,
        lanes: u32,
        thread_mode: ThreadMode,
        pwd: Vec<u8>,
        salt: Vec<u8>,
        secret: Vec<u8>,
        ad: Vec<u8>,
        hash_length: u32
    ) -> Result<Context> {
        if lanes < common::MIN_LANES {
            return Err(Error::LanesTooFew);
        } else if lanes > common::MAX_LANES {
            return Err(Error::LanesTooMany);
        }

        if mem_cost < common::MIN_MEMORY {
            return Err(Error::MemoryTooLittle);
        } else if mem_cost > common::MAX_MEMORY {
            return Err(Error::MemoryTooMuch);
        } else if mem_cost < 8 * lanes {
            return Err(Error::MemoryTooLittle);
        }

        if time_cost < common::MIN_TIME {
            return Err(Error::TimeTooSmall);
        } else if time_cost > common::MAX_TIME {
            return Err(Error::TimeTooLarge);
        }

        let pwd_len = pwd.len();
        if pwd_len < common::MIN_PWD_LENGTH as usize {
            return Err(Error::PwdTooShort);
        } else if pwd_len > common::MAX_PWD_LENGTH as usize {
            return Err(Error::PwdTooLong);
        }

        let salt_len = salt.len();
        if salt_len < common::MIN_SALT_LENGTH as usize {
            return Err(Error::SaltTooShort);
        } else if salt_len > common::MAX_SALT_LENGTH as usize {
            return Err(Error::SaltTooLong);
        }

        let secret_len = secret.len();
        if secret_len < common::MIN_SECRET_LENGTH as usize {
            return Err(Error::SecretTooShort);
        } else if secret_len > common::MAX_SECRET_LENGTH as usize {
            return Err(Error::SecretTooLong);
        }

        let ad_len = ad.len();
        if ad_len < common::MIN_AD_LENGTH as usize {
            return Err(Error::AdTooShort);
        } else if ad_len > common::MAX_AD_LENGTH as usize {
            return Err(Error::AdTooLong);
        }

        if hash_length < common::MIN_HASH_LENGTH {
            return Err(Error::OutputTooShort);
        } else if hash_length > common::MAX_HASH_LENGTH {
            return Err(Error::OutputTooLong);
        }

        let mut memory_blocks = mem_cost;
        if memory_blocks < 2 * common::SYNC_POINTS * lanes {
            memory_blocks = 2 * common::SYNC_POINTS * lanes;
        }

        let segment_length = memory_blocks / (lanes * common::SYNC_POINTS);
        let memory_blocks = segment_length * (lanes * common::SYNC_POINTS);
        let lane_length = segment_length * common::SYNC_POINTS;

        Ok(Context {
            ad: ad,
            hash_length: hash_length,
            lane_length: lane_length,
            lanes: lanes,
            mem_cost: mem_cost,
            memory_blocks: memory_blocks,
            pwd: pwd,
            salt: salt,
            secret: secret,
            segment_length: segment_length,
            thread_mode: thread_mode,
            time_cost: time_cost,
            variant: variant,
            version: version,
        })
    }
}


#[cfg(test)]
mod tests {

    use error::Error;
    use super::*;
    use variant::Variant;
    use version::Version;

    #[test]
    fn new_returns_correct_instance() {
        let variant = Variant::Argon2i;
        let version = Version::Version13;
        let mem_cost = 4096;
        let time_cost = 3;
        let lanes = 4;
        let thread_mode = ThreadMode::Sequential;
        let pwd = b"password";
        let salt = b"somesalt";
        let secret = b"secret";
        let ad = b"additionaldata";
        let hash_length = 32;
        let result = Context::new(variant,
                                  version,
                                  mem_cost,
                                  time_cost,
                                  lanes,
                                  thread_mode,
                                  pwd.to_vec(),
                                  salt.to_vec(),
                                  secret.to_vec(),
                                  ad.to_vec(),
                                  hash_length);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.variant, variant);
        assert_eq!(context.version, version);
        assert_eq!(context.mem_cost, mem_cost);
        assert_eq!(context.time_cost, time_cost);
        assert_eq!(context.lanes, lanes);
        assert_eq!(context.thread_mode, thread_mode);
        assert_eq!(context.pwd, pwd.to_vec());
        assert_eq!(context.salt, salt.to_vec());
        assert_eq!(context.secret, secret.to_vec());
        assert_eq!(context.ad, ad.to_vec());
        assert_eq!(context.hash_length, hash_length);
        assert_eq!(context.memory_blocks, 4096);
        assert_eq!(context.segment_length, 256);
        assert_eq!(context.lane_length, 1024);
    }

    #[test]
    fn new_with_too_little_mem_cost_returns_correct_error() {
        let mem_cost = 7;
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  mem_cost,
                                  3,
                                  4,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  vec![0u8; 8],
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  32);
        assert_eq!(result, Err(Error::MemoryTooLittle));
    }

    #[test]
    fn new_with_less_than_8_x_lanes_mem_cost_returns_correct_error() {
        let lanes = 4;
        let mem_cost = 31;
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  mem_cost,
                                  3,
                                  lanes,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  vec![0u8; 8],
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  32);
        assert_eq!(result, Err(Error::MemoryTooLittle));
    }

    #[test]
    fn new_with_too_small_time_cost_returns_correct_error() {
        let time_cost = 0;
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  4096,
                                  time_cost,
                                  4,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  vec![0u8; 8],
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  32);
        assert_eq!(result, Err(Error::TimeTooSmall));
    }

    #[test]
    fn new_with_too_few_lanes_returns_correct_error() {
        let lanes = 0;
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  4096,
                                  3,
                                  lanes,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  vec![0u8; 8],
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  32);
        assert_eq!(result, Err(Error::LanesTooFew));
    }

    #[test]
    fn new_with_too_many_lanes_returns_correct_error() {
        let lanes = 1 << 24;
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  4096,
                                  3,
                                  lanes,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  vec![0u8; 8],
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  32);
        assert_eq!(result, Err(Error::LanesTooMany));
    }

    #[test]
    fn new_with_too_short_salt_returns_correct_error() {
        let salt = vec![0u8; 7];
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  4096,
                                  3,
                                  4,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  salt,
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  32);
        assert_eq!(result, Err(Error::SaltTooShort));
    }

    #[test]
    fn new_with_too_short_hash_length_returns_correct_error() {
        let hash_length = 3;
        let result = Context::new(Variant::Argon2i,
                                  Version::Version13,
                                  4096,
                                  3,
                                  4,
                                  ThreadMode::Sequential,
                                  vec![0u8; 8],
                                  vec![0u8; 8],
                                  Vec::with_capacity(0),
                                  Vec::with_capacity(0),
                                  hash_length);
        assert_eq!(result, Err(Error::OutputTooShort));
    }
}
