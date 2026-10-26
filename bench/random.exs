# Random data: libsodium's randombytes against OTP crypto's strong_rand_bytes.
#
# Run from the repository root:
#   gmake && elixir bench/random.exs
#   BENCH_SIZES=16,4096 BENCH_TIME=1 elixir bench/random.exs
# Defaults: 32 bytes, 1 KiB, and 1 MiB, 0.5 seconds per scenario after 0.1 seconds of warmup.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()
randombytes = :libsodium_randombytes
IO.puts("randombytes implementation: #{randombytes.implementation_name()}")

buffers =
  for bytes <- B.sizes("32,1024,1048576"), reduce: [] do
    cases ->
      ^bytes = byte_size(randombytes.buf(bytes))

      cases ++
        [
          B.bench(
            "Random bytes",
            "#{B.size_label(bytes)}",
            "libsodium",
            fn -> randombytes.buf(bytes) end,
            bytes
          ),
          B.bench(
            "Random bytes",
            "#{B.size_label(bytes)}",
            "crypto",
            fn -> :crypto.strong_rand_bytes(bytes) end,
            bytes
          )
        ]
  end

# OTP's uniform integers from a cryptographically strong source go through rand.
strong = :crypto.rand_seed_alg_s(:crypto)

integers = [
  B.bench("Random integer", "uniform below 1000", "libsodium", fn -> randombytes.uniform(1000) end),
  B.bench("Random integer", "uniform below 1000", "crypto (rand)", fn ->
    :rand.uniform_s(1000, strong)
  end)
]

B.run("Random data", buffers ++ integers)
