# Key derivation: libsodium's HKDF and BLAKE2b-based crypto_kdf, against HKDF
# built from OTP crypto's HMAC (OTP has no HKDF function).
#
# Run from the repository root:
#   gmake && elixir bench/kdf.exs
#   BENCH_TIME=1 elixir bench/kdf.exs
# Default: 0.5 seconds per scenario after 0.1 seconds of warmup. Inputs are 32 bytes;
# outputs are 32 and 1024 bytes.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

defmodule CryptoHKDF do
  @moduledoc "RFC 5869 HKDF over :crypto.mac/4, as an OTP baseline."
  def extract(digest, salt, ikm), do: :crypto.mac(:hmac, digest, salt, ikm)

  def expand(digest, prk, info, length) do
    {okm, _} =
      Enum.reduce_while(Stream.iterate(1, &(&1 + 1)), {<<>>, <<>>}, fn counter, {okm, previous} ->
        if byte_size(okm) >= length do
          {:halt, {okm, previous}}
        else
          block = :crypto.mac(:hmac, digest, prk, <<previous::binary, info::binary, counter>>)
          {:cont, {okm <> block, block}}
        end
      end)

    binary_part(okm, 0, length)
  end
end

B.setup!()

ikm = :crypto.strong_rand_bytes(32)
salt = :crypto.strong_rand_bytes(32)
info = "libsodium benchmark"

hkdf =
  Enum.flat_map(
    [
      {"HKDF-SHA-256", :libsodium_crypto_kdf_hkdf_sha256, :sha256},
      {"HKDF-SHA-512", :libsodium_crypto_kdf_hkdf_sha512, :sha512}
    ],
    fn {name, module, digest} ->
      prk =
        B.same!("#{name} extract", [
          module.extract(salt, ikm),
          CryptoHKDF.extract(digest, salt, ikm)
        ])

      extract = [
        B.bench(name, "extract", "libsodium", fn -> module.extract(salt, ikm) end),
        B.bench(name, "extract", "crypto (HMAC)", fn -> CryptoHKDF.extract(digest, salt, ikm) end)
      ]

      expand =
        Enum.flat_map([32, 1024], fn length ->
          B.same!("#{name} expand", [
            module.expand(length, info, prk),
            CryptoHKDF.expand(digest, prk, info, length)
          ])

          [
            B.bench(name, "expand #{length} B", "libsodium", fn ->
              module.expand(length, info, prk)
            end),
            B.bench(name, "expand #{length} B", "crypto (HMAC)", fn ->
              CryptoHKDF.expand(digest, prk, info, length)
            end)
          ]
        end)

      extract ++ expand
    end
  )

kdf = :libsodium_crypto_kdf
master = kdf.keygen()

blake2b =
  for length <- [32, 64] do
    B.bench("BLAKE2b crypto_kdf", "derive #{length} B", "libsodium", fn ->
      kdf.derive_from_key(length, 1, "Examples", master)
    end)
  end

B.run("Key derivation", hkdf ++ blake2b)
