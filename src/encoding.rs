// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::context::Context;
use base64;

/// Gets the base64 encoded length of a byte slice with the specified length.
pub fn base64_len(length: u32) -> u32 {
    let olen = (length / 3) << 2;
    match length % 3 {
        2 => olen + 3,
        1 => olen + 2,
        _ => olen,
    }
}

/// Encodes the hash and context.
pub fn encode_string(context: &Context, hash: &[u8]) -> String {
    format!(
        "${}$v={}$m={},t={},p={}${}${}",
        context.config.variant,
        context.config.version,
        context.config.mem_cost,
        context.config.time_cost,
        context.config.lanes,
        base64::encode_config(context.salt, base64::STANDARD_NO_PAD),
        base64::encode_config(hash, base64::STANDARD_NO_PAD),
    )
}

/// Gets the string length of the specified number.
pub fn num_len(number: u32) -> u32 {
    let mut len = 1;
    let mut num = number;
    while num >= 10 {
        len += 1;
        num /= 10;
    }
    len
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "crossbeam-utils")]
    use crate::config::Config;
    #[cfg(feature = "crossbeam-utils")]
    use crate::context::Context;
    use crate::digest::Digest;
    #[cfg(feature = "crossbeam-utils")]
    use crate::encoding::encode_string;
    use crate::encoding::{base64_len, num_len};
    use crate::error::Error;
    #[cfg(feature = "crossbeam-utils")]
    use crate::thread_mode::ThreadMode;
    use crate::variant::Variant;
    use crate::version::Version;

    #[test]
    fn base64_len_returns_correct_length() {
        let tests = vec![
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 6),
            (5, 7),
            (6, 8),
            (7, 10),
            (8, 11),
            (9, 12),
            (10, 14),
        ];
        for (len, expected) in tests {
            let actual = base64_len(len);
            assert_eq!(actual, expected);
        }
    }

    #[cfg(feature = "crossbeam-utils")]
    #[test]
    fn encode_string_returns_correct_string() {
        let hash = b"12345678901234567890123456789012".to_vec();
        let config = Config {
            ad: &[],
            hash_length: hash.len() as u32,
            lanes: 1,
            mem_cost: 4096,
            secret: &[],
            thread_mode: ThreadMode::Parallel,
            time_cost: 3,
            variant: Variant::Argon2i,
            version: Version::Version13,
        };
        let pwd = b"password".to_vec();
        let salt = b"salt1234".to_vec();
        let context = Context::new(config, &pwd, &salt).unwrap();
        let expected = "$argon2i$v=19$m=4096,t=3,p=1\
                        $c2FsdDEyMzQ$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI";
        let actual = encode_string(&context, &hash);
        assert_eq!(actual, expected);
    }

    #[test]
    fn num_len_returns_correct_length() {
        let tests = vec![
            (1, 1),
            (10, 2),
            (110, 3),
            (1230, 4),
            (12340, 5),
            (123457, 6),
        ];
        for (num, expected) in tests {
            let actual = num_len(num);
            assert_eq!(actual, expected);
        }
    }
}
