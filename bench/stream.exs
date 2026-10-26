# Stream ciphers: libsodium's ChaCha20, XChaCha20, Salsa20, and XSalsa20 keystreams
# against OTP crypto's ChaCha20.
#
# Run from the repository root:
#   gmake && elixir bench/stream.exs
#   BENCH_SIZES=64,16384 BENCH_TIME=1 elixir bench/stream.exs
# Defaults: 1 KiB and 1 MiB messages, 0.5 seconds per scenario after 0.1 seconds of warmup.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()

cases =
  for bytes <- B.sizes(), reduce: [] do
    cases ->
      message = :binary.copy(<<0>>, bytes)
      operation = "xor #{B.size_label(bytes)}"

      # OTP's 16-byte ChaCha20 IV is a 32-bit little-endian block counter followed by the IETF nonce.
      chacha20 = :libsodium_crypto_stream_chacha20
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)

      B.same!("ChaCha20", [
        chacha20.ietf_xor(message, nonce, key),
        :crypto.crypto_one_time(:chacha20, key, <<0::32, nonce::binary>>, message, true)
      ])

      chacha = [
        B.bench(
          "ChaCha20 (IETF)",
          operation,
          "libsodium",
          fn -> chacha20.ietf_xor(message, nonce, key) end,
          bytes
        ),
        B.bench(
          "ChaCha20 (IETF)",
          operation,
          "crypto",
          fn ->
            :crypto.crypto_one_time(:chacha20, key, <<0::32, nonce::binary>>, message, true)
          end,
          bytes
        )
      ]

      others =
        for {name, module} <- [
              {"XChaCha20", :libsodium_crypto_stream_xchacha20},
              {"Salsa20", :libsodium_crypto_stream_salsa20},
              {"Salsa20/12", :libsodium_crypto_stream_salsa2012},
              {"XSalsa20", :libsodium_crypto_stream_xsalsa20}
            ] do
          key = module.keygen()
          nonce = :crypto.strong_rand_bytes(module.noncebytes())
          ^message = module.xor(module.xor(message, nonce, key), nonce, key)
          B.bench(name, operation, "libsodium", fn -> module.xor(message, nonce, key) end, bytes)
        end

      cases ++ chacha ++ others
  end

B.run("Stream ciphers", cases)
