# Changelog

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
