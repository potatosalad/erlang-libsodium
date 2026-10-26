# Key agreement and encapsulation: X25519, crypto_box and crypto_kx precomputation,
# and the ML-KEM-768 and X-Wing KEMs, against OTP crypto's X25519 and ML-KEM-768.
#
# Run from the repository root:
#   gmake && elixir bench/key_exchange.exs
#   BENCH_TIME=1 elixir bench/key_exchange.exs
# Default: 0.5 seconds per scenario after 0.1 seconds of warmup.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()

# X25519: libsodium clamps the scalar, as OTP does.
x25519 = :libsodium_crypto_scalarmult_curve25519
{alice_pub, alice_priv} = :crypto.generate_key(:eddh, :x25519)
{bob_pub, _bob_priv} = :crypto.generate_key(:eddh, :x25519)
^alice_pub = x25519.base(alice_priv)

B.same!("X25519 shared secret", [
  x25519.crypto_scalarmult_curve25519(alice_priv, bob_pub),
  :crypto.compute_key(:eddh, bob_pub, alice_priv, :x25519)
])

x25519_cases = [
  B.bench("X25519", "public key", "libsodium", fn -> x25519.base(alice_priv) end),
  B.bench("X25519", "public key", "crypto", fn ->
    :crypto.generate_key(:eddh, :x25519, alice_priv)
  end),
  B.bench("X25519", "shared secret", "libsodium", fn ->
    x25519.crypto_scalarmult_curve25519(alice_priv, bob_pub)
  end),
  B.bench("X25519", "shared secret", "crypto", fn ->
    :crypto.compute_key(:eddh, bob_pub, alice_priv, :x25519)
  end)
]

box = :libsodium_crypto_box
{box_pk, box_sk} = box.seed_keypair(:crypto.strong_rand_bytes(32))
kx = :libsodium_crypto_kx
{client_pk, client_sk} = kx.seed_keypair(:crypto.strong_rand_bytes(32))
{server_pk, _server_sk} = kx.seed_keypair(:crypto.strong_rand_bytes(32))

precompute = [
  B.bench("crypto_box", "beforenm", "libsodium", fn -> box.beforenm(box_pk, box_sk) end),
  B.bench("crypto_kx", "client session keys", "libsodium", fn ->
    kx.client_session_keys(client_pk, client_sk, server_pk)
  end)
]

# ML-KEM-768 keys and ciphertexts interoperate between libsodium and OTP crypto.
mlkem = :libsodium_crypto_kem_mlkem768
{pk, sk} = mlkem.keypair()
{ct, ss} = mlkem.enc(pk)
^ss = mlkem.dec(ct, sk)
{otp_pub, otp_priv} = :crypto.generate_key(:mlkem768, [])
{otp_ss, otp_ct} = :crypto.encapsulate_key(:mlkem768, otp_pub)
^otp_ss = :crypto.decapsulate_key(:mlkem768, otp_priv, otp_ct)
^ss = :crypto.decapsulate_key(:mlkem768, sk, ct)
^otp_ss = mlkem.dec(otp_ct, otp_priv)

mlkem_cases = [
  B.bench("ML-KEM-768", "keypair", "libsodium", fn -> mlkem.keypair() end),
  B.bench("ML-KEM-768", "keypair", "crypto", fn -> :crypto.generate_key(:mlkem768, []) end),
  B.bench("ML-KEM-768", "encapsulate", "libsodium", fn -> mlkem.enc(pk) end),
  B.bench("ML-KEM-768", "encapsulate", "crypto", fn ->
    :crypto.encapsulate_key(:mlkem768, otp_pub)
  end),
  B.bench("ML-KEM-768", "decapsulate", "libsodium", fn -> mlkem.dec(ct, sk) end),
  B.bench("ML-KEM-768", "decapsulate", "crypto", fn ->
    :crypto.decapsulate_key(:mlkem768, otp_priv, otp_ct)
  end)
]

xwing = :libsodium_crypto_kem_xwing
{xpk, xsk} = xwing.keypair()
{xct, xss} = xwing.enc(xpk)
^xss = xwing.dec(xct, xsk)

xwing_cases = [
  B.bench("X-Wing (default crypto_kem)", "keypair", "libsodium", fn -> xwing.keypair() end),
  B.bench("X-Wing (default crypto_kem)", "encapsulate", "libsodium", fn -> xwing.enc(xpk) end),
  B.bench("X-Wing (default crypto_kem)", "decapsulate", "libsodium", fn -> xwing.dec(xct, xsk) end)
]

B.run("Key agreement and encapsulation", x25519_cases ++ precompute ++ mlkem_cases ++ xwing_cases)
