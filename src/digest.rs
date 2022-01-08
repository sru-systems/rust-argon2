// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{fmt, str::FromStr};

use crate::error::Error;
use crate::error::Error::DecodingFail;
use crate::result::Result;
use crate::variant::Variant;
use crate::version::Version;

/// Parsed representation of the [Argon2] hash in encoded form.
///
/// You can parse [`Digest`] hash from the [`str`] by [`FromStr`]
/// implementation of this structure.
///
/// [`Digest`] can be used for password verification with a
/// [`argon2::verify_digest`] function.
///
/// [Argon2]: https://en.wikipedia.org/wiki/Argon2
/// [`argon2::verify_digest`]: crate::verify_digest
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Digest {
    /// The variant of [Argon2] being used.
    ///
    /// [Argon2]: https://en.wikipedia.org/wiki/Argon2
    pub variant: Variant,

    /// The version of [Argon2] being used.
    ///
    /// [Argon2]: https://en.wikipedia.org/wiki/Argon2
    pub version: Version,

    /// The amount of memory requested (KiB).
    pub mem_cost: u32,

    /// The number of iterations (or passes) over the memory.
    pub time_cost: u32,

    /// The number of threads (or lanes) used by the algorithm.
    pub parallelism: u32,

    /// The salt.
    pub salt: Vec<u8>,

    /// The hash.
    pub hash: Vec<u8>,
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "${}$v={}$m={},t={},p={}${}${}",
            self.variant,
            self.version,
            self.mem_cost,
            self.time_cost,
            self.parallelism,
            base64::encode_config(&self.salt, base64::STANDARD_NO_PAD),
            base64::encode_config(&self.hash, base64::STANDARD_NO_PAD),
        )
    }
}

impl FromStr for Digest {
    type Err = Error;

    /// Attempts to decode the encoded string slice.
    fn from_str(encoded: &str) -> Result<Self> {
        let items: Vec<&str> = encoded.split('$').take(6).collect();
        if !items[0].is_empty() {
            return Err(DecodingFail);
        }
        if items.len() == 6 {
            let options = Options::from_str(items[3])?;
            Ok(Digest {
                variant: items[1].parse()?,
                version: decode_option(items[2], "v")?,
                mem_cost: options.mem_cost,
                time_cost: options.time_cost,
                parallelism: options.parallelism,
                salt: base64::decode(items[4])?,
                hash: base64::decode(items[5])?,
            })
        } else if items.len() == 5 {
            let options = Options::from_str(items[2])?;
            Ok(Digest {
                variant: items[1].parse()?,
                version: Version::Version10,
                mem_cost: options.mem_cost,
                time_cost: options.time_cost,
                parallelism: options.parallelism,
                salt: base64::decode(items[3])?,
                hash: base64::decode(items[4])?,
            })
        } else {
            Err(DecodingFail)
        }
    }
}

fn decode_option<T: FromStr>(s: &str, name: &str) -> Result<T> {
    let mut items = s.split('=');
    if items.next() != Some(name) {
        return Err(DecodingFail);
    }
    let option = items
        .next()
        .and_then(|val| val.parse().ok())
        .ok_or(DecodingFail)?;

    if items.next().is_none() {
        Ok(option)
    } else {
        Err(DecodingFail)
    }
}

/// Structure containing the options.
struct Options {
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl FromStr for Options {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut items = s.split(',');
        let out = Self {
            mem_cost: decode_option(items.next().ok_or(DecodingFail)?, "m")?,
            time_cost: decode_option(items.next().ok_or(DecodingFail)?, "t")?,
            parallelism: decode_option(items.next().ok_or(DecodingFail)?, "p")?,
        };

        if items.next().is_none() {
            Ok(out)
        } else {
            Err(DecodingFail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_string_with_version10_returns_correct_result() {
        let encoded = "$argon2i$v=16$m=4096,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let expected = Digest {
            variant: Variant::Argon2i,
            version: Version::Version10,
            mem_cost: 4096,
            time_cost: 3,
            parallelism: 1,
            salt: b"salt1234".to_vec(),
            hash: b"12345678901234567890123456789012".to_vec(),
        };
        let actual = Digest::from_str(encoded).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn decode_string_with_version13_returns_correct_result() {
        let encoded = "$argon2i$v=19$m=4096,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let expected = Digest {
            variant: Variant::Argon2i,
            version: Version::Version13,
            mem_cost: 4096,
            time_cost: 3,
            parallelism: 1,
            salt: b"salt1234".to_vec(),
            hash: b"12345678901234567890123456789012".to_vec(),
        };
        let actual = Digest::from_str(encoded).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn decode_string_without_version_returns_correct_result() {
        let encoded = "$argon2i$m=4096,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let expected = Digest {
            variant: Variant::Argon2i,
            version: Version::Version10,
            mem_cost: 4096,
            time_cost: 3,
            parallelism: 1,
            salt: b"salt1234".to_vec(),
            hash: b"12345678901234567890123456789012".to_vec(),
        };
        let actual = Digest::from_str(encoded).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn decode_string_without_variant_returns_error_result() {
        let encoded = "$m=4096,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_empty_variant_returns_error_result() {
        let encoded = "$$m=4096,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_invalid_variant_returns_error_result() {
        let encoded = "$argon$m=4096,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_without_mem_cost_returns_error_result() {
        let encoded = "$argon2i$t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_empty_mem_cost_returns_error_result() {
        let encoded = "$argon2i$m=,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_non_numeric_mem_cost_returns_error_result() {
        let encoded = "$argon2i$m=a,t=3,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_without_time_cost_returns_error_result() {
        let encoded = "$argon2i$m=4096,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_empty_time_cost_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_non_numeric_time_cost_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=a,p=1\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_without_parallelism_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=3\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_empty_parallelism_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=3,p=\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_non_numeric_parallelism_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=3,p=a\
                       $c2FsdDEyMzQ=$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_without_salt_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=3,p=1\
                       $MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_without_hash_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=3,p=a\
                       $c2FsdDEyMzQ=";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }

    #[test]
    fn decode_string_with_empty_hash_returns_error_result() {
        let encoded = "$argon2i$m=4096,t=3,p=a\
                       $c2FsdDEyMzQ=$";
        let result = Digest::from_str(encoded);
        assert_eq!(result, Err(Error::DecodingFail));
    }
}
