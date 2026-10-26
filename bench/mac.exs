# Message authentication: libsodium's HMACs, Poly1305, keyed BLAKE2b, and SipHash
# against OTP crypto's HMAC and Poly1305.
#
# Run from the repository root:
#   gmake && elixir bench/mac.exs
#   BENCH_SIZES=64,16384 BENCH_TIME=1 elixir bench/mac.exs
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
      operation = "authenticate #{B.size_label(bytes)}"
      verify = "verify #{B.size_label(bytes)}"

      # HMAC-SHA-512/256 is HMAC-SHA-512 truncated to 32 bytes.
      hmacs =
        Enum.flat_map(
          [
            {"HMAC-SHA-256", :libsodium_crypto_auth_hmacsha256, :crypto_auth_hmacsha256, :sha256,
             32},
            {"HMAC-SHA-512", :libsodium_crypto_auth_hmacsha512, :crypto_auth_hmacsha512, :sha512,
             64},
            {"HMAC-SHA-512/256", :libsodium_crypto_auth_hmacsha512256, :crypto_auth_hmacsha512256,
             :sha512, 32}
          ],
          fn {name, module, one_shot, digest, length} ->
            key = module.keygen()
            stream = fn -> module.final(module.update(module.init(key), message)) end
            crypto = fn -> :crypto.macN(:hmac, digest, key, message, length) end
            tag = B.same!(name, [apply(module, one_shot, [message, key]), stream.(), crypto.()])
            0 = module.verify(tag, message, key)

            [
              B.bench(
                name,
                operation,
                "libsodium",
                fn -> apply(module, one_shot, [message, key]) end,
                bytes
              ),
              B.bench(name, operation, "libsodium streaming", stream, bytes),
              B.bench(name, operation, "crypto", crypto, bytes),
              B.bench(
                name,
                verify,
                "libsodium",
                fn -> module.verify(tag, message, key) end,
                bytes
              ),
              B.bench(
                name,
                verify,
                "crypto",
                fn ->
                  :crypto.hash_equals(tag, :crypto.macN(:hmac, digest, key, message, length))
                end,
                bytes
              )
            ]
          end
        )

      poly1305 = :libsodium_crypto_onetimeauth_poly1305
      poly_key = poly1305.keygen()
      poly_stream = fn -> poly1305.final(poly1305.update(poly1305.init(poly_key), message)) end

      B.same!("Poly1305", [
        poly1305.crypto_onetimeauth_poly1305(message, poly_key),
        poly_stream.(),
        :crypto.mac(:poly1305, poly_key, message)
      ])

      generichash = :libsodium_crypto_generichash
      blake_key = generichash.keygen()
      siphash = :libsodium_crypto_shorthash_siphash24
      sip_key = :crypto.strong_rand_bytes(siphash.keybytes())

      others = [
        B.bench(
          "Poly1305",
          operation,
          "libsodium",
          fn ->
            poly1305.crypto_onetimeauth_poly1305(message, poly_key)
          end,
          bytes
        ),
        B.bench("Poly1305", operation, "libsodium streaming", poly_stream, bytes),
        B.bench(
          "Poly1305",
          operation,
          "crypto",
          fn -> :crypto.mac(:poly1305, poly_key, message) end,
          bytes
        ),
        B.bench(
          "Keyed BLAKE2b-256",
          operation,
          "libsodium",
          fn ->
            generichash.crypto_generichash(message, blake_key)
          end,
          bytes
        ),
        B.bench(
          "SipHash-2-4",
          operation,
          "libsodium",
          fn ->
            siphash.crypto_shorthash_siphash24(message, sip_key)
          end,
          bytes
        )
      ]

      cases ++ hmacs ++ others
  end

B.run("Message authentication", cases)
