# Changelog

## Unreleased

* Breaking changes
  * Requires Erlang/OTP 27 or later (module documentation uses `-moduledoc`/`-doc`); CI covers OTP 28 and 29.
  * The port driver, `libsodium_server`, and `include/libsodium.hrl` are gone. `libsodium:call/2,3` remains as a
    deprecated shim over `libsodium_nif`; `libsodium:call/4`, `open/0`, and `close/1` are removed, as are the
    internal `call/1,2` exports of each namespace module.
  * Arguments that are not binaries or integers now raise `badarg` instead of `function_clause`.
  * The `libsodium` application no longer depends on `crypto`, `asn1`, or `public_key`.
* Enhancements
  * Generate the native and Erlang sources, the test suite, `ex_doc.config`, and `README.md` from YAML definitions
    under `codegen/` with `just codegen` (or `just docker-codegen`), mirroring `libdecaf`: generated files are
    formatted and carry a content signature, and README examples run against the built library.
  * Replace the port driver with a NIF (`libsodium_nif`). Calls over 64 KiB of input or output move to a dirty CPU
    scheduler, password hashing always runs on one, and streaming `update/2` functions yield whenever their
    timeslice is exhausted.
  * Every module has module and function documentation, specs, and multiline exports.
  * Modernize `c_src/Makefile`: build libsodium out of tree into `c_deps/libsodium-build`, track header
    dependencies, and add `format`, `lint-format`, and sanitizer (`SANITIZE=1`) support.
  * New functions:
    * `libsodium_crypto_box_curve25519xchacha20poly1305:seal/2`, `seal_open/3`, and `sealbytes/0`
    * `libsodium_crypto_onetimeauth_poly1305:statebytes/0`
    * `libsodium_randombytes:buf_deterministic/2`
    * `libsodium_runtime:has_armcrypto/0`
    * `libsodium_utils:sub/2` (implemented by the port driver but never exported), `memcmp/2`, `ip2bin/1`, and
      `bin2ip/1`
    * `libsodium_version:library_minimal/0`
  * HMAC `init/1` functions accept keys of any length, as libsodium does.
* Fixes
  * `libsodium_crypto_aead_aes256gcm:beforenm/1` and the `_afternm` functions are available again: states are
    copied into properly aligned memory instead of crashing the VM.
  * `libsodium_crypto_sign_ed25519:init/0`, `update/2`, `final_create/2`, and `final_verify/3` now work; the port
    driver never implemented them.
  * The NaCl-style `libsodium_crypto_secretbox:crypto_secretbox/3` and `open/3` (and their xsalsa20poly1305
    equivalents) returned uninitialized memory and overflowed a stack buffer; they now follow NaCl's padded
    format exactly.
  * Opening a ciphertext shorter than the authentication tag (`open_easy` for boxes and secret boxes) returns `-1`
    instead of overflowing the stack.
  * Outputs are allocated as binaries instead of stack arrays sized by the input, so large messages can no longer
    overflow the stack, and every output buffer is wiped before release. Several port driver memory leaks are gone.
  * libsodium is no longer configured with `--enable-opt`, which tuned the build for the compiling machine's CPU.

## 2.0.0 (2022-08-31)

* Fixes
  * Include `Makefile` in hex.pm package so it works correctly with erlang.mk
  * Ditching the version tag matching upstream libsodium library since hex.pm requires semantic versioning :-( (which is really a good thing, I'm just whining that I can't break the rules just this once).

## 1.0.18 (2022-08-31)

* Library Support
  * Update to [libsodium 1.0.18](https://github.com/jedisct1/libsodium/releases/tag/1.0.18).
  * Removed (deprecated upstream)
    * `crypto_core_salsa208`
    * `crypto_stream_aes128ctr`
    * `crypto_stream_salsa208`
  * Added
    * `crypto_aead_xchacha20poly1305`
    * `crypto_box_curve25519xchacha20poly1305`
    * `crypto_core_ed25519`
    * `crypto_core_hchacha20`
    * `crypto_core_ristretto255`
    * `crypto_kdf`
    * `crypto_kdf_blake2b`
    * `crypto_kx`
    * `crypto_pwhash_argon2id`
    * `crypto_scalarmult_ed25519`
    * `crypto_scalarmult_ristretto255`
    * `crypto_secretbox`
    * `crypto_secretbox_xchacha20poly1305`
    * `crypto_secretbox_xsalsa20poly1305`
    * `crypto_secretstream_xchacha20poly1305`
    * `crypto_shorthash_siphashx24`
    * `crypto_sign_ed25519ph`
    * `crypto_stream_xchacha20`
    * `crypto_verify_16`
    * `crypto_verify_32`
    * `crypto_verify_64`
    * `sodium_base64_encoded_len`
    * `sodium_base642bin`
    * `sodium_bin2base64`
    * `sodium_pad`
    * `sodium_sub`
    * `sodium_unpad`
* Enhancements
  * Switch from Travis CI to GitHub Actions.
  * Relicense library under MIT license.
  * Update version tag to match upstream libsodium library.

* Enhancements
  * Add detached functions to `libsodium_crypto_aead_aes256gcm`:
    * `encrypt_detached/3`
    * `encrypt_detached/4`
    * `decrypt_detached/4`
    * `decrypt_detached/5`

## 0.0.10 (2016-10-14)

* Enhancements
  * Add detached functions to `libsodium_crypto_aead_aes256gcm`:
    * `encrypt_detached/3`
    * `encrypt_detached/4`
    * `decrypt_detached/4`
    * `decrypt_detached/5`

## 0.0.9 (2016-10-04)

* Fixes
  * Segfault when using `libsodium_crypto_box:seal_open/3` where ciphertext length is less than sealbytes. (See [#5](https://github.com/potatosalad/erlang-libsodium/pull/5), thanks to [@mtaylor91](https://github.com/mtaylor91))

## 0.0.8 (2016-08-08)

* Library Support
  * Update to [libsodium 1.0.11](https://github.com/jedisct1/libsodium/releases/tag/1.0.11).

## 0.0.7 (2016-05-31)

* Library Support
  * `libsodium_crypto_aead_chacha20poly1305` detached mode and IETF compliance.

## 0.0.6 (2016-05-24)

* Enhancements
  * Tests for the `crypto_pwhash` group.

* Fixes
  * Minor fixes to the following libraries:
    * `libsodium_crypto_pwhash`
    * `libsodium_crypto_pwhash_argon2i`
    * `libsodium_crypto_pwhash_scryptsalsa208sha256`

## 0.0.5 (2016-05-24)

* Library Support
  * Update to [libsodium 1.0.10](https://github.com/jedisct1/libsodium/releases/tag/1.0.10).
  * `libsodium_crypto_pwhash` (See #2)
  * `libsodium_crypto_pwhash_argon2i` (See #2)

## 0.0.4 (2016-03-10)

* Library Support
  * `libsodium_crypto_pwhash_scryptsalsa208sha256` (See #1)

## 0.0.3 (2016-02-05)

* Fixes
  * Minor fixes to build flags and port driver lookup.

## 0.0.2 (2016-01-16)

* Publish to [hex.pm](https://hex.pm/packages/libsodium) without binary files.

## 0.0.1 (2016-01-16)

* Initial Release

* Library Support
  * `libsodium_crypto_aead_aes256gcm`
  * `libsodium_crypto_aead_chacha20poly1305`
  * `libsodium_crypto_auth`
  * `libsodium_crypto_auth_hmacsha256`
  * `libsodium_crypto_auth_hmacsha512`
  * `libsodium_crypto_auth_hmacsha512256`
  * `libsodium_crypto_box`
  * `libsodium_crypto_box_curve25519xsalsa20poly1305`
  * `libsodium_crypto_core_hsalsa20`
  * `libsodium_crypto_core_salsa20`
  * `libsodium_crypto_core_salsa2012`
  * `libsodium_crypto_core_salsa208`
  * `libsodium_crypto_generichash`
  * `libsodium_crypto_generichash_blake2b`
  * `libsodium_crypto_hash`
  * `libsodium_crypto_hash_sha256`
  * `libsodium_crypto_hash_sha512`
  * `libsodium_crypto_onetimeauth`
  * `libsodium_crypto_onetimeauth_poly1305`
  * `libsodium_crypto_scalarmult`
  * `libsodium_crypto_scalarmult_curve25519`
  * `libsodium_crypto_shorthash`
  * `libsodium_crypto_shorthash_siphash24`
  * `libsodium_crypto_sign`
  * `libsodium_crypto_sign_ed25519`
  * `libsodium_crypto_stream`
  * `libsodium_crypto_stream_aes128ctr`
  * `libsodium_crypto_stream_chacha20`
  * `libsodium_crypto_stream_salsa20`
  * `libsodium_crypto_stream_salsa2012`
  * `libsodium_crypto_stream_salsa208`
  * `libsodium_crypto_stream_xsalsa20`
  * `libsodium_randombytes`
  * `libsodium_runtime`
  * `libsodium_utils`
  * `libsodium_version`

* Basic Tests
  * `aead_aes256gcm`
  * `aead_chacha20poly1305`
  * `sign`
