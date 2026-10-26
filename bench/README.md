# Benchmarks

[Benchee](https://github.com/bencheeorg/benchee) scripts that compare libsodium's
implementations with each other and, where OTP has an equivalent, with the
Erlang/OTP `crypto` application. Before timing anything, each script checks that
the implementations it compares produce identical results (and that keys,
signatures, and ciphertexts interoperate where that applies).

```sh
gmake
just bench              # every script
just bench aead         # one script, or: elixir bench/aead.exs
```

The scripts use `Mix.install/1`, so they need Elixir and network access on the
first run. They load the library from `ebin/`. Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BENCH_SIZES` | `1024,1048576` | Comma-separated message sizes in bytes |
| `BENCH_TIME` | `0.5` (`2` for `pwhash`) | Seconds measured per scenario |
| `BENCH_WARMUP` | `0.1` (`0.5` for `pwhash`) | Seconds of warmup per scenario |
| `BENCH_LIMITS` | `interactive,moderate` | Password hashing limits (`pwhash` only) |

| Script | libsodium | OTP `crypto` baseline |
| --- | --- | --- |
| `aead.exs` | ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM, AEGIS-128L/256, secretbox, secretstream | ChaCha20-Poly1305, AES-256-GCM |
| `hash.exs` | SHA-2, SHA-3, BLAKE2b, SHAKE, TurboSHAKE (one-shot and streaming) | SHA-2, SHA-3, BLAKE2b-512, SHAKE (one-shot and streaming) |
| `mac.exs` | HMAC-SHA-256/512/512256, Poly1305, keyed BLAKE2b, SipHash-2-4 | HMAC, Poly1305 |
| `stream.exs` | ChaCha20, XChaCha20, Salsa20, Salsa20/12, XSalsa20 | ChaCha20 |
| `sign.exs` | Ed25519, Ed25519ph | Ed25519 |
| `key_exchange.exs` | X25519, `crypto_box` and `crypto_kx` precomputation, ML-KEM-768, X-Wing | X25519, ML-KEM-768 |
| `kdf.exs` | HKDF-SHA-256/512, BLAKE2b `crypto_kdf` | HKDF built from HMAC |
| `pwhash.exs` | Argon2id, Argon2i, scrypt | none (OTP has no memory-hard password hash) |
| `random.exs` | `randombytes` | `strong_rand_bytes/1`, `rand` with the `crypto` generator |

Each script prints Benchee's results for every algorithm and operation, then a
comparison table. Messages over 64 KiB make libsodium's one-shot calls run on a
dirty CPU scheduler; streaming variants stay on normal schedulers and yield.

## Results

Measured 2026-10-26 on an Apple M3 Max (14 schedulers online), Erlang/OTP 29.1.2,
Elixir 1.20.4, libsodium 1.0.22, and OpenSSL 3.5.9 behind OTP `crypto`, with the
default settings above and one calling process. MB/s is decimal megabytes of
message per second. "vs crypto" compares the fastest libsodium variant with
`crypto`; above 1.00x, libsodium is faster. Results depend on the CPU, the
OpenSSL build, and other load, so treat them as indicative.

What stands out on this machine:

- libsodium is faster for public-key work: Ed25519 key generation, and signing and
  verifying short messages (2.4–4.3x), X25519 (2.2–3.0x), and ML-KEM-768
  (1.8–4.8x). It is also faster for short messages with AES-256-GCM, BLAKE2b,
  SHAKE, and HKDF.
- OpenSSL is faster for bulk SHA-2 (and so HMAC and signing long Ed25519
  messages), ChaCha20, and Poly1305, where it uses ARMv8 assembly and libsodium
  uses portable code. AEGIS-128L and AEGIS-256, which OTP lacks, are the fastest
  AEADs here.
- `randombytes` asks the operating system (`sysrandom`) on every call, so it is
  slower than the user-space generator behind `strong_rand_bytes/1`.

### Authenticated encryption

`aead.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| AEGIS-128L | decrypt 1 KiB | libsodium | 3397 MB/s | - | - |
| AEGIS-128L | decrypt 1 MiB | libsodium | 12021 MB/s | - | - |
| AEGIS-128L | encrypt 1 KiB | libsodium | 4487 MB/s | - | - |
| AEGIS-128L | encrypt 1 MiB | libsodium | 14127 MB/s | - | - |
| AEGIS-256 | decrypt 1 KiB | libsodium | 2507 MB/s | - | - |
| AEGIS-256 | decrypt 1 MiB | libsodium | 7334 MB/s | - | - |
| AEGIS-256 | encrypt 1 KiB | libsodium | 3946 MB/s | - | - |
| AEGIS-256 | encrypt 1 MiB | libsodium | 7954 MB/s | - | - |
| AES-256-GCM | decrypt 1 KiB | libsodium precomputed | 2714 MB/s | 1594 MB/s | 1.70x |
| AES-256-GCM | decrypt 1 MiB | libsodium precomputed | 6830 MB/s | 8500 MB/s | 0.80x |
| AES-256-GCM | encrypt 1 KiB | libsodium precomputed | 3053 MB/s | 1781 MB/s | 1.71x |
| AES-256-GCM | encrypt 1 MiB | libsodium precomputed | 6609 MB/s | 8043 MB/s | 0.82x |
| ChaCha20-Poly1305 | decrypt 1 KiB | libsodium detached | 554 MB/s | 984 MB/s | 0.56x |
| ChaCha20-Poly1305 | decrypt 1 MiB | libsodium detached | 650 MB/s | 2045 MB/s | 0.32x |
| ChaCha20-Poly1305 | encrypt 1 KiB | libsodium | 552 MB/s | 954 MB/s | 0.58x |
| ChaCha20-Poly1305 | encrypt 1 MiB | libsodium | 641 MB/s | 2038 MB/s | 0.31x |
| XChaCha20-Poly1305 | decrypt 1 KiB | libsodium | 474 MB/s | - | - |
| XChaCha20-Poly1305 | decrypt 1 MiB | libsodium | 618 MB/s | - | - |
| XChaCha20-Poly1305 | encrypt 1 KiB | libsodium | 536 MB/s | - | - |
| XChaCha20-Poly1305 | encrypt 1 MiB | libsodium | 639 MB/s | - | - |
| XChaCha20-Poly1305 secretstream | pull 1 KiB | libsodium | 492 MB/s | - | - |
| XChaCha20-Poly1305 secretstream | pull 1 MiB | libsodium | 661 MB/s | - | - |
| XChaCha20-Poly1305 secretstream | push 1 KiB | libsodium | 487 MB/s | - | - |
| XChaCha20-Poly1305 secretstream | push 1 MiB | libsodium | 646 MB/s | - | - |
| XSalsa20-Poly1305 secretbox | decrypt 1 KiB | libsodium | 503 MB/s | - | - |
| XSalsa20-Poly1305 secretbox | decrypt 1 MiB | libsodium | 661 MB/s | - | - |
| XSalsa20-Poly1305 secretbox | encrypt 1 KiB | libsodium | 549 MB/s | - | - |
| XSalsa20-Poly1305 secretbox | encrypt 1 MiB | libsodium | 640 MB/s | - | - |

### Hashing and XOFs

`hash.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| BLAKE2b-256 (generichash) | hash 1 KiB | libsodium | 1118 MB/s | - | - |
| BLAKE2b-256 (generichash) | hash 1 MiB | libsodium keyed | 1262 MB/s | - | - |
| BLAKE2b-512 | hash 1 KiB | libsodium | 960 MB/s | 856 MB/s | 1.12x |
| BLAKE2b-512 | hash 1 MiB | libsodium | 1263 MB/s | 991 MB/s | 1.27x |
| SHA-256 | hash 1 KiB | libsodium | 376 MB/s | 1035 MB/s | 0.36x |
| SHA-256 | hash 1 MiB | libsodium streaming | 437 MB/s | 2510 MB/s | 0.17x |
| SHA-512 | hash 1 KiB | libsodium | 562 MB/s | 1176 MB/s | 0.48x |
| SHA-512 | hash 1 MiB | libsodium streaming | 682 MB/s | 1567 MB/s | 0.44x |
| SHA3-256 | hash 1 KiB | libsodium | 779 MB/s | 768 MB/s | 1.01x |
| SHA3-256 | hash 1 MiB | libsodium streaming | 872 MB/s | 961 MB/s | 0.91x |
| SHA3-512 | hash 1 KiB | libsodium | 421 MB/s | 361 MB/s | 1.17x |
| SHA3-512 | hash 1 MiB | libsodium streaming | 466 MB/s | 520 MB/s | 0.90x |
| SHAKE128 | absorb 1 KiB | libsodium | 858 MB/s | 574 MB/s | 1.50x |
| SHAKE128 | absorb 1 MiB | libsodium streaming | 1093 MB/s | 1151 MB/s | 0.95x |
| SHAKE256 | absorb 1 KiB | libsodium | 721 MB/s | 527 MB/s | 1.37x |
| SHAKE256 | absorb 1 MiB | libsodium streaming | 888 MB/s | 861 MB/s | 1.03x |
| TurboSHAKE128 | absorb 1 KiB | libsodium | 1443 MB/s | - | - |
| TurboSHAKE128 | absorb 1 MiB | libsodium streaming | 1929 MB/s | - | - |
| TurboSHAKE256 | absorb 1 KiB | libsodium | 1314 MB/s | - | - |
| TurboSHAKE256 | absorb 1 MiB | libsodium streaming | 1679 MB/s | - | - |

### Message authentication

`mac.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| HMAC-SHA-256 | authenticate 1 KiB | libsodium | 333 MB/s | 707 MB/s | 0.47x |
| HMAC-SHA-256 | authenticate 1 MiB | libsodium streaming | 439 MB/s | 2512 MB/s | 0.17x |
| HMAC-SHA-256 | verify 1 KiB | libsodium | 328 MB/s | 682 MB/s | 0.48x |
| HMAC-SHA-256 | verify 1 MiB | libsodium | 419 MB/s | 2508 MB/s | 0.17x |
| HMAC-SHA-512 | authenticate 1 KiB | libsodium | 422 MB/s | 534 MB/s | 0.79x |
| HMAC-SHA-512 | authenticate 1 MiB | libsodium streaming | 689 MB/s | 1519 MB/s | 0.45x |
| HMAC-SHA-512 | verify 1 KiB | libsodium | 400 MB/s | 498 MB/s | 0.80x |
| HMAC-SHA-512 | verify 1 MiB | libsodium | 663 MB/s | 1517 MB/s | 0.44x |
| HMAC-SHA-512/256 | authenticate 1 KiB | libsodium | 424 MB/s | 539 MB/s | 0.79x |
| HMAC-SHA-512/256 | authenticate 1 MiB | libsodium streaming | 689 MB/s | 1512 MB/s | 0.46x |
| HMAC-SHA-512/256 | verify 1 KiB | libsodium | 407 MB/s | 526 MB/s | 0.77x |
| HMAC-SHA-512/256 | verify 1 MiB | libsodium | 619 MB/s | 1470 MB/s | 0.42x |
| Keyed BLAKE2b-256 | authenticate 1 KiB | libsodium | 1010 MB/s | - | - |
| Keyed BLAKE2b-256 | authenticate 1 MiB | libsodium | 1259 MB/s | - | - |
| Poly1305 | authenticate 1 KiB | libsodium | 2133 MB/s | 1973 MB/s | 1.08x |
| Poly1305 | authenticate 1 MiB | libsodium streaming | 2551 MB/s | 6830 MB/s | 0.37x |
| SipHash-2-4 | authenticate 1 KiB | libsodium | 1817 MB/s | - | - |
| SipHash-2-4 | authenticate 1 MiB | libsodium | 1913 MB/s | - | - |

### Stream ciphers

`stream.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| ChaCha20 (IETF) | xor 1 KiB | libsodium | 784 MB/s | 1097 MB/s | 0.71x |
| ChaCha20 (IETF) | xor 1 MiB | libsodium | 850 MB/s | 2540 MB/s | 0.33x |
| Salsa20 | xor 1 KiB | libsodium | 790 MB/s | - | - |
| Salsa20 | xor 1 MiB | libsodium | 826 MB/s | - | - |
| Salsa20/12 | xor 1 KiB | libsodium | 1229 MB/s | - | - |
| Salsa20/12 | xor 1 MiB | libsodium | 1460 MB/s | - | - |
| XChaCha20 | xor 1 KiB | libsodium | 731 MB/s | - | - |
| XChaCha20 | xor 1 MiB | libsodium | 854 MB/s | - | - |
| XSalsa20 | xor 1 KiB | libsodium | 755 MB/s | - | - |
| XSalsa20 | xor 1 MiB | libsodium | 850 MB/s | - | - |

### Signatures

`sign.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| Ed25519 | keypair from seed | libsodium | 95.11 K op/s | 33.35 K op/s | 2.85x |
| Ed25519 | sign 1 KiB | libsodium | 72.83 MB/s | 17.08 MB/s | 4.26x |
| Ed25519 | sign 1 MiB | libsodium | 338 MB/s | 771 MB/s | 0.44x |
| Ed25519 | verify 1 KiB | libsodium | 31.63 MB/s | 13.11 MB/s | 2.41x |
| Ed25519 | verify 1 MiB | libsodium | 668 MB/s | 1438 MB/s | 0.46x |
| Ed25519ph (streaming) | sign 1 KiB | libsodium | 76.43 MB/s | - | - |
| Ed25519ph (streaming) | sign 1 MiB | libsodium | 680 MB/s | - | - |
| Ed25519ph (streaming) | verify 1 KiB | libsodium | 30.93 MB/s | - | - |
| Ed25519ph (streaming) | verify 1 MiB | libsodium | 684 MB/s | - | - |

### Key agreement and encapsulation

`key_exchange.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| ML-KEM-768 | decapsulate | libsodium | 56.06 K op/s | 11.59 K op/s | 4.84x |
| ML-KEM-768 | encapsulate | libsodium | 62.40 K op/s | 34.62 K op/s | 1.80x |
| ML-KEM-768 | keypair | libsodium | 60.86 K op/s | 30.06 K op/s | 2.02x |
| X-Wing (default crypto_kem) | decapsulate | libsodium | 14.22 K op/s | - | - |
| X-Wing (default crypto_kem) | encapsulate | libsodium | 19.20 K op/s | - | - |
| X-Wing (default crypto_kem) | keypair | libsodium | 38.16 K op/s | - | - |
| X25519 | public key | libsodium | 100 K op/s | 33.65 K op/s | 2.98x |
| X25519 | shared secret | libsodium | 38.17 K op/s | 17.63 K op/s | 2.16x |
| crypto_box | beforenm | libsodium | 38.37 K op/s | - | - |
| crypto_kx | client session keys | libsodium | 38.22 K op/s | - | - |

### Key derivation

`kdf.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| BLAKE2b crypto_kdf | derive 32 B | libsodium | 4.98 M op/s | - | - |
| BLAKE2b crypto_kdf | derive 64 B | libsodium | 3.79 M op/s | - | - |
| HKDF-SHA-256 | expand 1024 B | libsodium | 46.87 K op/s | 27.23 K op/s | 1.72x |
| HKDF-SHA-256 | expand 32 B | libsodium | 1.31 M op/s | 699 K op/s | 1.87x |
| HKDF-SHA-256 | extract | libsodium | 1.30 M op/s | 952 K op/s | 1.36x |
| HKDF-SHA-512 | expand 1024 B | libsodium | 74.67 K op/s | 42.34 K op/s | 1.76x |
| HKDF-SHA-512 | expand 32 B | libsodium | 1.06 M op/s | 610 K op/s | 1.73x |
| HKDF-SHA-512 | extract | libsodium | 1.02 M op/s | 803 K op/s | 1.26x |

### Password hashing

`pwhash.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| Argon2i | hash interactive (32 MiB) | libsodium | 19.47 op/s | - | - |
| Argon2i | hash moderate (128 MiB) | libsodium | 2.77 op/s | - | - |
| Argon2i | verify interactive (32 MiB) | libsodium | 19.04 op/s | - | - |
| Argon2i | verify moderate (128 MiB) | libsodium | 2.80 op/s | - | - |
| Argon2id | hash interactive (64 MiB) | libsodium | 16.33 op/s | - | - |
| Argon2id | hash moderate (256 MiB) | libsodium | 2.65 op/s | - | - |
| Argon2id | verify interactive (64 MiB) | libsodium | 17.17 op/s | - | - |
| Argon2id | verify moderate (256 MiB) | libsodium | 2.67 op/s | - | - |
| scrypt | hash interactive (16 MiB) | libsodium | 38.67 op/s | - | - |
| scrypt | verify interactive (16 MiB) | libsodium | 38.91 op/s | - | - |

### Random data

`random.exs`

| Algorithm | Operation | Fastest libsodium variant | libsodium | crypto | vs crypto |
| --- | --- | --- | ---: | ---: | ---: |
| Random bytes | 1 KiB | libsodium | 357 MB/s | 2467 MB/s | 0.14x |
| Random bytes | 1 MiB | libsodium | 375 MB/s | 11374 MB/s | 0.03x |
| Random bytes | 32 B | libsodium | 25.17 MB/s | 132 MB/s | 0.19x |
| Random integer | uniform below 1000 | libsodium | 975 K op/s | 2.10 M op/s | 0.46x |
