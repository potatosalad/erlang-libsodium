# Migrating to 3.0

Version 3.0 replaces the port driver with a NIF and generates every module from
libsodium's API definitions. Function names, arities, argument order, default
arguments, and the `-1` results for failed decryption and verification are
unchanged, so most code keeps working. This guide covers what does change.

## Requirements

- Erlang/OTP 27 or later. Module and function documentation use `-moduledoc` and
  `-doc`; CI tests OTP 28 and 29.
- A C compiler and `make`, as before. The vendored libsodium 1.0.22 is compiled
  into the NIF; no system library is used.

Starting the application is optional: the NIF loads on first use.
`libsodium:start/0` still starts it and its dependencies, which are now only
`kernel` and `stdlib` (the port driver also required `crypto`, `asn1`, and
`public_key`).

## States are opaque resources

Streaming and precomputed states used to be binaries holding a raw C struct.
They are now opaque NIF resources, typed as each module's `state()`:

| Module | Functions |
| --- | --- |
| `libsodium_crypto_generichash`, `libsodium_crypto_generichash_blake2b` | `init`, `update`, `final` |
| `libsodium_crypto_hash_sha256`, `libsodium_crypto_hash_sha512` | `init`, `update`, `final` |
| `libsodium_crypto_auth_hmacsha256`, `…_hmacsha512`, `…_hmacsha512256` | `init`, `update`, `final` |
| `libsodium_crypto_onetimeauth`, `libsodium_crypto_onetimeauth_poly1305` | `init`, `update`, `final` |
| `libsodium_crypto_sign`, `libsodium_crypto_sign_ed25519`, `libsodium_crypto_sign_ed25519ph` | `init`, `update`, `final_create`, `final_verify` |
| `libsodium_crypto_secretstream_xchacha20poly1305` | `init_push`, `push`, `init_pull`, `pull`, `rekey` |
| `libsodium_crypto_aead_aes256gcm` | `beforenm` and the `_afternm` functions |

Code that threads states through these functions needs no change:

```erlang
State0 = libsodium_crypto_hash_sha256:init(),
State1 = libsodium_crypto_hash_sha256:update(State0, <<"a">>),
State2 = libsodium_crypto_hash_sha256:update(State1, <<"bc">>),
Digest = libsodium_crypto_hash_sha256:final(State2),
Digest = libsodium_crypto_hash_sha256:crypto_hash_sha256(<<"abc">>).
```

Operations never modify their argument; each returns a new state. Earlier
states remain valid, so a state can be reused (for example, to hash several
messages with a common prefix) or sent to another process:

```erlang
Prefix = libsodium_crypto_hash_sha256:update(libsodium_crypto_hash_sha256:init(), <<"prefix:">>),
A = libsodium_crypto_hash_sha256:final(libsodium_crypto_hash_sha256:update(Prefix, <<"a">>)),
B = libsodium_crypto_hash_sha256:final(libsodium_crypto_hash_sha256:update(Prefix, <<"b">>)),
true = A =/= B.
```

What no longer works:

- **Inspecting or storing states.** `byte_size/1` and pattern matching on a state
  fail, and a state cannot be written to disk, sent to another node, or
  restored with `binary_to_term/1` in another VM. Finish the operation and store
  its result instead. `statebytes/0` still reports libsodium's size for the
  state but has no meaning for Erlang code.
- **Passing a binary as a state.** It raises `badarg`, as does passing one
  module's state to another module (for example, a SHA-256 state to
  `libsodium_crypto_hash_sha512:update/2`).

`libsodium_crypto_sign_ed25519:init/0` and the other Ed25519 streaming functions
used to fail with every input; they now work.

## Errors

- Arguments of the wrong type now raise `badarg` instead of `function_clause`,
  the same error as for binaries of the wrong length.
- A few inputs that crashed or overflowed buffers in the port driver now return
  `-1`, such as ciphertexts shorter than the authentication tag passed to
  `open_easy`, and out-of-range output lengths for password hashing and key
  derivation.
- `libsodium_crypto_stream_chacha20:ietf_xor_ic/4` raises `badarg` when its block
  counter would overflow, instead of aborting the VM.

## Removed functions

| Removed | Replacement |
| --- | --- |
| `call/4`, `open/0`, and `close/1` in the `libsodium` module | None; there is no port. |
| `call/1` and `call/2` in every namespace module | Call the module's functions directly. |

`libsodium:call/2,3` remain for code that dispatched by name, but are deprecated
and compile with a warning. Replace `libsodium:call(crypto_box, keypair, {})`
with `libsodium_crypto_box:keypair()`.

## Types and Dialyzer

Every function now has a spec, and fixed-size arguments and results have exact
types, such as `libsodium_crypto_aead_aes256gcm:k()` (`<<_:256>>`) and
`npub()` (`<<_:96>>`). Constants with a fixed value are typed as that value
(`keybytes() -> 32`), and bounded integers as ranges. Dialyzer may now report
calls that pass values which cannot be valid, such as a hard-coded key of the
wrong length.

## Scheduling

All calls used to go through one port and the async thread pool. The NIF runs
small calls on the calling process's scheduler. It moves calls that process more
than 64 KiB, and all password hashing, to dirty CPU schedulers, and streaming
`update` functions yield between chunks. Long operations therefore no longer
serialize behind one another, and no process blocks a scheduler.

## New functionality

Version 3.0 adds AEGIS-128L and AEGIS-256, HKDF-SHA256/512, SHA3-256/512,
SHAKE and TurboSHAKE, the ML-KEM-768 and X-Wing post-quantum KEMs, ipcrypt, and
the Keccak-f[1600] permutation, along with smaller additions listed in the
[changelog](../CHANGELOG.md).
