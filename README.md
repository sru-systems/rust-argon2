# Rust-argon2

Rust library for hashing passwords using
[Argon2](https://github.com/P-H-C/phc-winner-argon2), the password-hashing
function that won the
[Password Hashing Competition (PHC)](https://password-hashing.net).

## Usage

To use `rust-argon2`, add the following to your Cargo.toml:

```toml
[dependencies]
rust-argon2 = "0.2.0"
```

And the following to your crate root:

```rust
extern crate argon2;
```


## Examples

Create a password hash using the defaults and verify it:

```rust
use argon2::{self, Config};

let password = b"password";
let salt = b"randomsalt";
let config = Config::default();
let hash = argon2::hash_encoded(password, salt, &config).unwrap();
let matches = argon2::verify_encoded(&hash, password).unwrap();
assert!(matches);
```

Create a password hash with custom settings and verify it:

```rust
use argon2::{self, Config, ThreadMode, Variant, Version};

let password = b"password";
let salt = b"othersalt";
let config = Config {
    variant: Variant::Argon2i,
    version: Version::Version13,
    mem_cost: 65536,
    time_cost: 10,
    lanes: 4,
    thread_mode: ThreadMode::Parallel,
    secret: &[],
    ad: &[],
    hash_length: 32
};
let hash = argon2::hash_encoded(password, salt, &config).unwrap();
let matches = argon2::verify_encoded(&hash, password).unwrap();
assert!(matches);
```


## Limitations

This crate has the same limitation as the `blake2-rfc` crate that it uses.
It does not attempt to clear potentially sensitive data from its work
memory. To do so correctly without a heavy performance penalty would
require help from the compiler. It's better to not attempt to do so than to
present a false assurance.

This version uses the standard implementation and does not yet implement
optimizations. Therefore, it is not the fastest implementation available.


## License

Rust-argon2 is dual licensed under the [MIT](LICENSE-MIT) and
[Apache 2.0](LICENSE-APACHE) licenses, the same licenses as the Rust compiler.


## Contributions

Contributions are welcome. By submitting a pull request you are agreeing to
make you work available under the license terms of the Rust-argon2 project.


## History

### Version 0.2.0

This version added a `Config` struct. Due to this struct the `hash_encoded`,
`hash_raw` and `verify_raw` functions were changed in a non backward
compatible way. However, the previous functionality is still available by
using `hash_encoded_old`, `hash_raw_old` and `verify_raw_old`.

The following functions are deprecated since this version:

- `hash_encoded_defaults`
- `hash_encoded_old`
- `hash_encoded_std`
- `hash_raw_defaults`
- `hash_raw_old`
- `hash_raw_std`
- `verify_raw_old`
- `verify_raw_std`
