ChangeLog for rust-argon2
=========================

This documents all notable changes to
[rust-argon2](https://github.com/sru-systems/rust-argon2).

## 3.0.0

- Bring back parallelism (by Jonas Malaco).
- Update base64 dependency to 0.22.
- Update constant_time_eq dependency to 0.4.2.


## 2.1.0

- Add OWASP recommended configurations.
- Change default configuration from RFC9106 to OWASP (t=2, 19 MiB memory). For
  the 2.0.0 default configuration use `Config::rfc9106`. For the 1.0.x default
  configuration use `Config::original`.

## 2.0.0

- Remove parallel execution to prevent UB.
- Add config settings from RFC9106.
- Use RFC9106 recommended settings as default.


## 1.0.1

- Update serde dependency to 1.0.
- Update constant_time_eq dependency to 0.3.0.
- Update base64 dependency to 0.21.
- Encoded strings must not use padding, fix tests.
- Update to Rust edition 2021.


## 1.0.0

- Remove deprecated functions.
- Update constant_time_eq to 0.1.5.
- Update serde to 1.0.133.
- Update blake2b_simd to 1.0.


## 0.8.3

- Replace transmute with to_le_bytes.
- Update base64 to version 0.13.
- Update crossbeam-utils to version 0.8.
- Update hex to version 0.4.
- Derive Clone for Error struct.
- Add optional serde support for Error struct.


## 0.8.2

- Change base64 to latest version (0.12).


## 0.8.1

- Fix issue with verifying multi-lane hashes with parallelism disabled (#27)

## 0.8.0

- Make parallelism optional via feature flag.


## 0.7.0

- Update crossbeam-utils dependency to 0.7.


## 0.6.1

- Use constant time equals to compare hashes.


## 0.6.0

- Use 2018 edition or Rust
- Use &dyn error::Error instead of &error::Error
- Fix clippy lints
- Allow callers of encode_string to pass any &[u8]
- Update base64 dependency.


## 0.5.1

- Use crossbeam utils 0.6 instead of crossbeam 0.5


## 0.5.0

- Replace blake2-rfc with blake2b_simd.


## 0.4.0

- Replace rustc-serialize dependency with base64 and hex.
- Update base64 dependency.
- Update crossbeam dependency.
- Update hex dependency.
- Allow updating to minor versions of blake2-rfc.


## 0.3.0

- Embed Config struct in Context struct.


## 0.2.0

- Use ThreadMode enum instead of explicit thread number.
- Use a Config struct instead of explicit configuration arguments.
- Use references instead of vectors for byte data in the Context struct.
- Deprecate the following functions:
  - hash_encoded_defaults
  - hash_encoded_old
  - hash_encoded_std
  - hash_raw_defaults
  - hash_raw_old
  - hash_raw_std
  - verify_raw_old
  - verify_raw_std
