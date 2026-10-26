# Password hashing: Argon2id, Argon2i, and scrypt at libsodium's interactive and
# moderate limits. OTP crypto has no memory-hard password hash, so these compare
# libsodium's algorithms and limits with each other.
#
# Run from the repository root:
#   gmake && elixir bench/pwhash.exs
#   BENCH_TIME=5 BENCH_LIMITS=interactive,moderate,sensitive elixir bench/pwhash.exs
# Defaults: interactive and moderate limits, 2 seconds per scenario after 0.5 seconds of warmup.
# Every call runs on a dirty CPU scheduler.

Mix.install([{:benchee, "~> 1.5.1"}])
Code.prepend_path(Path.expand("../ebin", __DIR__))
Code.require_file("support/libsodium_bench.exs", __DIR__)

alias LibsodiumBench, as: B

B.setup!()
System.put_env("BENCH_TIME", System.get_env("BENCH_TIME", "2"))
System.put_env("BENCH_WARMUP", System.get_env("BENCH_WARMUP", "0.5"))

limits =
  System.get_env("BENCH_LIMITS", "interactive,moderate")
  |> String.split(",", trim: true)

password = "correct horse battery staple"

cases =
  for limit <- limits,
      {name, module} <- [
        {"Argon2id", :libsodium_crypto_pwhash_argon2id},
        {"Argon2i", :libsodium_crypto_pwhash_argon2i},
        {"scrypt", :libsodium_crypto_pwhash_scryptsalsa208sha256}
      ],
      # scrypt has no moderate limits.
      Code.ensure_loaded?(module) and
        function_exported?(module, String.to_atom("opslimit_#{limit}"), 0),
      reduce: [] do
    cases ->
      ops = apply(module, String.to_atom("opslimit_#{limit}"), [])
      mem = apply(module, String.to_atom("memlimit_#{limit}"), [])
      hash = module.str(password, ops, mem)
      0 = module.str_verify(hash, password)
      operation = "#{limit} (#{div(mem, 1024 * 1024)} MiB)"

      cases ++
        [
          B.bench(name, "hash #{operation}", "libsodium", fn -> module.str(password, ops, mem) end),
          B.bench(name, "verify #{operation}", "libsodium", fn ->
            module.str_verify(hash, password)
          end)
        ]
  end

B.run("Password hashing", cases)
