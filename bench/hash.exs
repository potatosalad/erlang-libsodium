# Hashing and extendable output: one-shot and streaming libsodium hashes against
# OTP crypto's SHA-2, SHA-3, BLAKE2b, and SHAKE.
#
# Run from the repository root:
#   gmake && elixir bench/hash.exs
#   BENCH_SIZES=64,16384 BENCH_TIME=1 elixir bench/hash.exs
# Defaults: 1 KiB and 1 MiB messages, 0.5 seconds per scenario after 0.1 seconds of warmup.
# Streaming variants absorb the whole message in one update call; XOFs squeeze 32 bytes.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()

# {name, module, one-shot function, crypto hash or nil, extra init arguments}
hashes = [
  {"SHA-256", :libsodium_crypto_hash_sha256, :crypto_hash_sha256, :sha256},
  {"SHA-512", :libsodium_crypto_hash_sha512, :crypto_hash_sha512, :sha512},
  {"SHA3-256", :libsodium_crypto_hash_sha3256, :crypto_hash_sha3256, :sha3_256},
  {"SHA3-512", :libsodium_crypto_hash_sha3512, :crypto_hash_sha3512, :sha3_512}
]

cases =
  for bytes <- B.sizes(), reduce: [] do
    cases ->
      message = :binary.copy(<<0>>, bytes)
      operation = "hash #{B.size_label(bytes)}"

      sha =
        Enum.flat_map(hashes, fn {name, module, one_shot, crypto} ->
          stream = fn -> module.final(module.update(module.init(), message)) end

          B.same!(name, [
            apply(module, one_shot, [message]),
            stream.(),
            :crypto.hash(crypto, message)
          ])

          [
            B.bench(
              name,
              operation,
              "libsodium",
              fn -> apply(module, one_shot, [message]) end,
              bytes
            ),
            B.bench(name, operation, "libsodium streaming", stream, bytes),
            B.bench(name, operation, "crypto", fn -> :crypto.hash(crypto, message) end, bytes),
            B.bench(
              name,
              operation,
              "crypto streaming",
              fn ->
                :crypto.hash_final(:crypto.hash_update(:crypto.hash_init(crypto), message))
              end,
              bytes
            )
          ]
        end)

      # BLAKE2b with a 64-byte digest is the only length OTP crypto offers.
      blake2b = :libsodium_crypto_generichash_blake2b

      blake2b_stream = fn ->
        blake2b.final(blake2b.update(blake2b.init(<<>>, 64), message), 64)
      end

      B.same!("BLAKE2b-512", [
        blake2b.crypto_generichash_blake2b(64, message, <<>>),
        blake2b_stream.(),
        :crypto.hash(:blake2b, message)
      ])

      generichash = :libsodium_crypto_generichash
      key = generichash.keygen()

      blake =
        [
          B.bench(
            "BLAKE2b-512",
            operation,
            "libsodium",
            fn ->
              blake2b.crypto_generichash_blake2b(64, message, <<>>)
            end,
            bytes
          ),
          B.bench("BLAKE2b-512", operation, "libsodium streaming", blake2b_stream, bytes),
          B.bench(
            "BLAKE2b-512",
            operation,
            "crypto",
            fn -> :crypto.hash(:blake2b, message) end,
            bytes
          ),
          B.bench(
            "BLAKE2b-256 (generichash)",
            operation,
            "libsodium",
            fn ->
              generichash.crypto_generichash(message)
            end,
            bytes
          ),
          B.bench(
            "BLAKE2b-256 (generichash)",
            operation,
            "libsodium keyed",
            fn ->
              generichash.crypto_generichash(message, key)
            end,
            bytes
          )
        ]

      # Extendable output: 32 bytes from each XOF; crypto counts the output in bits.
      xofs =
        Enum.flat_map(
          [
            {"SHAKE128", :libsodium_crypto_xof_shake128, :crypto_xof_shake128, :shake128},
            {"SHAKE256", :libsodium_crypto_xof_shake256, :crypto_xof_shake256, :shake256},
            {"TurboSHAKE128", :libsodium_crypto_xof_turboshake128, :crypto_xof_turboshake128,
             nil},
            {"TurboSHAKE256", :libsodium_crypto_xof_turboshake256, :crypto_xof_turboshake256, nil}
          ],
          fn {name, module, one_shot, crypto} ->
            xof_operation = "absorb #{B.size_label(bytes)}"

            stream = fn ->
              {_, out} = module.squeeze(module.update(module.init(), message), 32)
              out
            end

            ours = [apply(module, one_shot, [32, message]), stream.()]
            theirs = if crypto, do: [:crypto.hash_xof(crypto, message, 256)], else: []
            B.same!(name, ours ++ theirs)

            [
              B.bench(
                name,
                xof_operation,
                "libsodium",
                fn -> apply(module, one_shot, [32, message]) end,
                bytes
              ),
              B.bench(name, xof_operation, "libsodium streaming", stream, bytes)
            ] ++
              if crypto,
                do: [
                  B.bench(
                    name,
                    xof_operation,
                    "crypto",
                    fn -> :crypto.hash_xof(crypto, message, 256) end,
                    bytes
                  )
                ],
                else: []
          end
        )

      cases ++ sha ++ blake ++ xofs
  end

B.run("Hashing", cases)
