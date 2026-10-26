# Authenticated encryption: libsodium's AEADs, secret boxes, and secret streams,
# against OTP crypto's ChaCha20-Poly1305 and AES-256-GCM.
#
# Run from the repository root:
#   gmake && elixir bench/aead.exs
#   BENCH_SIZES=64,16384 BENCH_TIME=1 elixir bench/aead.exs
# Defaults: 1 KiB and 1 MiB messages, 0.5 seconds per scenario after 0.1 seconds of warmup.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()

ad = :binary.copy(<<1>>, 32)

cases =
  for bytes <- B.sizes(), reduce: [] do
    cases ->
      size = B.size_label(bytes)
      message = :binary.copy(<<0>>, bytes)
      encrypt = "encrypt #{size}"
      decrypt = "decrypt #{size}"

      # ChaCha20-Poly1305 (IETF): combined and detached libsodium output versus crypto.
      chacha = :libsodium_crypto_aead_chacha20poly1305
      key = chacha.keygen()
      nonce = :crypto.strong_rand_bytes(chacha.ietf_npubbytes())
      {c, tag} = chacha.ietf_encrypt_detached(message, ad, nonce, key)
      {^c, ^tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, message, ad, true)
      combined = chacha.ietf_encrypt(message, ad, nonce, key)
      ^combined = c <> tag

      ^message =
        B.same!("ChaCha20-Poly1305 decrypt", [
          chacha.ietf_decrypt(combined, ad, nonce, key),
          chacha.ietf_decrypt_detached(c, tag, ad, nonce, key),
          :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, c, ad, tag, false)
        ])

      chacha_cases = [
        B.bench(
          "ChaCha20-Poly1305",
          encrypt,
          "libsodium",
          fn -> chacha.ietf_encrypt(message, ad, nonce, key) end,
          bytes
        ),
        B.bench(
          "ChaCha20-Poly1305",
          encrypt,
          "libsodium detached",
          fn ->
            chacha.ietf_encrypt_detached(message, ad, nonce, key)
          end,
          bytes
        ),
        B.bench(
          "ChaCha20-Poly1305",
          encrypt,
          "crypto",
          fn ->
            :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, message, ad, true)
          end,
          bytes
        ),
        B.bench(
          "ChaCha20-Poly1305",
          decrypt,
          "libsodium",
          fn -> chacha.ietf_decrypt(combined, ad, nonce, key) end,
          bytes
        ),
        B.bench(
          "ChaCha20-Poly1305",
          decrypt,
          "libsodium detached",
          fn ->
            chacha.ietf_decrypt_detached(c, tag, ad, nonce, key)
          end,
          bytes
        ),
        B.bench(
          "ChaCha20-Poly1305",
          decrypt,
          "crypto",
          fn ->
            :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, c, ad, tag, false)
          end,
          bytes
        )
      ]

      # AES-256-GCM: libsodium's hardware implementation (when the CPU has one) versus crypto.
      gcm = :libsodium_crypto_aead_aes256gcm
      gcm_key = :crypto.strong_rand_bytes(gcm.keybytes())
      gcm_nonce = :crypto.strong_rand_bytes(gcm.npubbytes())

      {gc, gtag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, gcm_key, gcm_nonce, message, ad, true)

      gcm_crypto = [
        B.bench(
          "AES-256-GCM",
          encrypt,
          "crypto",
          fn ->
            :crypto.crypto_one_time_aead(:aes_256_gcm, gcm_key, gcm_nonce, message, ad, true)
          end,
          bytes
        ),
        B.bench(
          "AES-256-GCM",
          decrypt,
          "crypto",
          fn ->
            :crypto.crypto_one_time_aead(:aes_256_gcm, gcm_key, gcm_nonce, gc, ad, gtag, false)
          end,
          bytes
        )
      ]

      gcm_cases =
        if gcm.is_available() == 1 do
          ctx = gcm.beforenm(gcm_key)
          ^gc = :binary.part(gcm.encrypt(message, ad, gcm_nonce, gcm_key), 0, bytes)
          {^gc, ^gtag} = gcm.encrypt_detached_afternm(message, ad, gcm_nonce, ctx)
          gcombined = gc <> gtag
          ^message = gcm.decrypt(gcombined, ad, gcm_nonce, gcm_key)

          gcm_crypto ++
            [
              B.bench(
                "AES-256-GCM",
                encrypt,
                "libsodium",
                fn -> gcm.encrypt(message, ad, gcm_nonce, gcm_key) end,
                bytes
              ),
              B.bench(
                "AES-256-GCM",
                encrypt,
                "libsodium precomputed",
                fn ->
                  gcm.encrypt_afternm(message, ad, gcm_nonce, ctx)
                end,
                bytes
              ),
              B.bench(
                "AES-256-GCM",
                decrypt,
                "libsodium",
                fn ->
                  gcm.decrypt(gcombined, ad, gcm_nonce, gcm_key)
                end,
                bytes
              ),
              B.bench(
                "AES-256-GCM",
                decrypt,
                "libsodium precomputed",
                fn ->
                  gcm.decrypt_afternm(gcombined, ad, gcm_nonce, ctx)
                end,
                bytes
              )
            ]
        else
          gcm_crypto
        end

      # Constructions without an OTP equivalent, compared with each other.
      aeads =
        Enum.flat_map(
          [
            {"XChaCha20-Poly1305", :libsodium_crypto_aead_xchacha20poly1305, "ietf_"},
            {"AEGIS-128L", :libsodium_crypto_aead_aegis128l, ""},
            {"AEGIS-256", :libsodium_crypto_aead_aegis256, ""}
          ],
          fn {name, module, prefix} ->
            [encrypt_fun, decrypt_fun, nonce_fun, keygen_fun] =
              Enum.map(~w(encrypt decrypt npubbytes keygen), &String.to_atom(prefix <> &1))

            key = apply(module, keygen_fun, [])
            nonce = :crypto.strong_rand_bytes(apply(module, nonce_fun, []))
            ciphertext = apply(module, encrypt_fun, [message, ad, nonce, key])
            ^message = apply(module, decrypt_fun, [ciphertext, ad, nonce, key])

            [
              B.bench(
                name,
                encrypt,
                "libsodium",
                fn -> apply(module, encrypt_fun, [message, ad, nonce, key]) end,
                bytes
              ),
              B.bench(
                name,
                decrypt,
                "libsodium",
                fn -> apply(module, decrypt_fun, [ciphertext, ad, nonce, key]) end,
                bytes
              )
            ]
          end
        )

      box = :libsodium_crypto_secretbox
      box_key = box.keygen()
      box_nonce = :crypto.strong_rand_bytes(box.noncebytes())
      boxed = box.easy(message, box_nonce, box_key)
      ^message = box.open_easy(boxed, box_nonce, box_key)

      stream = :libsodium_crypto_secretstream_xchacha20poly1305
      stream_key = stream.keygen()
      {push_state, header} = stream.init_push(stream_key)
      tag_message = stream.tag_message()
      {_, pushed} = stream.push(push_state, message, <<>>, tag_message)
      pull_state = stream.init_pull(header, stream_key)
      {_, ^message, ^tag_message} = stream.pull(pull_state, pushed, <<>>)

      others = [
        B.bench(
          "XSalsa20-Poly1305 secretbox",
          encrypt,
          "libsodium",
          fn -> box.easy(message, box_nonce, box_key) end,
          bytes
        ),
        B.bench(
          "XSalsa20-Poly1305 secretbox",
          decrypt,
          "libsodium",
          fn ->
            box.open_easy(boxed, box_nonce, box_key)
          end,
          bytes
        ),
        B.bench(
          "XChaCha20-Poly1305 secretstream",
          "push #{size}",
          "libsodium",
          fn ->
            stream.push(push_state, message, <<>>, tag_message)
          end,
          bytes
        ),
        B.bench(
          "XChaCha20-Poly1305 secretstream",
          "pull #{size}",
          "libsodium",
          fn ->
            stream.pull(pull_state, pushed, <<>>)
          end,
          bytes
        )
      ]

      cases ++ chacha_cases ++ gcm_cases ++ aeads ++ others
  end

B.run("Authenticated encryption", cases)
