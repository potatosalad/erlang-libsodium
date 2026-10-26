# Signatures: libsodium's Ed25519 and Ed25519ph against OTP crypto's Ed25519.
#
# Run from the repository root:
#   gmake && elixir bench/sign.exs
#   BENCH_SIZES=64,16384 BENCH_TIME=1 elixir bench/sign.exs
# Defaults: 1 KiB and 1 MiB messages, 0.5 seconds per scenario after 0.1 seconds of warmup.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()

ed25519 = :libsodium_crypto_sign_ed25519
ed25519ph = :libsodium_crypto_sign_ed25519ph
seed = :crypto.strong_rand_bytes(32)
{pk, sk} = ed25519.seed_keypair(seed)
{^pk, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)

keypair = [
  B.bench("Ed25519", "keypair from seed", "libsodium", fn -> ed25519.seed_keypair(seed) end),
  B.bench("Ed25519", "keypair from seed", "crypto", fn ->
    :crypto.generate_key(:eddsa, :ed25519, seed)
  end)
]

cases =
  for bytes <- B.sizes(), reduce: keypair do
    cases ->
      message = :binary.copy(<<0>>, bytes)
      size = B.size_label(bytes)

      signature =
        B.same!("Ed25519 sign", [
          ed25519.detached(message, sk),
          :crypto.sign(:eddsa, :none, message, [seed, :ed25519])
        ])

      0 = ed25519.verify_detached(signature, message, pk)
      true = :crypto.verify(:eddsa, :none, message, signature, [pk, :ed25519])

      ph_sign = fn -> ed25519ph.final_create(ed25519ph.update(ed25519ph.init(), message), sk) end
      ph_signature = ph_sign.()
      0 = ed25519ph.final_verify(ed25519ph.update(ed25519ph.init(), message), ph_signature, pk)

      cases ++
        [
          B.bench(
            "Ed25519",
            "sign #{size}",
            "libsodium",
            fn -> ed25519.detached(message, sk) end,
            bytes
          ),
          B.bench(
            "Ed25519",
            "sign #{size}",
            "crypto",
            fn ->
              :crypto.sign(:eddsa, :none, message, [seed, :ed25519])
            end,
            bytes
          ),
          B.bench(
            "Ed25519",
            "verify #{size}",
            "libsodium",
            fn ->
              ed25519.verify_detached(signature, message, pk)
            end,
            bytes
          ),
          B.bench(
            "Ed25519",
            "verify #{size}",
            "crypto",
            fn ->
              :crypto.verify(:eddsa, :none, message, signature, [pk, :ed25519])
            end,
            bytes
          ),
          B.bench("Ed25519ph (streaming)", "sign #{size}", "libsodium", ph_sign, bytes),
          B.bench(
            "Ed25519ph (streaming)",
            "verify #{size}",
            "libsodium",
            fn ->
              ed25519ph.final_verify(
                ed25519ph.update(ed25519ph.init(), message),
                ph_signature,
                pk
              )
            end,
            bytes
          )
        ]
  end

B.run("Signatures", cases)
