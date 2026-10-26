# Maintenance

- APIs: `src/`; native components: `c_src/nif/`; tests: `test/`. CI targets OTP 28/29.
- Generated files: edit `codegen/` inputs (`config.yaml`, `namespaces/*.yaml`, templates), run `just codegen`, commit inputs and outputs. See `codegen/README.md`.
- Hand-written sources: `c_src/nif/libsodium_nif.h`, `c_src/nif/core/`, `src/libsodium_app.erl`, `src/libsodium_sup.erl`, `test/libsodium_SUITE.erl`, `test/libsodium_ct.erl`.
- Python dependencies: edit `codegen/pyproject.toml`, run `just lock`, include `poetry.lock` and `requirements.txt`.
- Run `gmake format`, `gmake tests`, `gmake lint`, and `gmake docs`; generator checks: `cd codegen && poetry run pytest`.
- Benchmarks: `just bench [script]` runs `bench/*.exs` (Benchee via `Mix.install`); each script cross-checks outputs before timing. Update `bench/README.md` when results change materially.
- Erlang: multiline exports, named specs, module docs and metadata. Keep generated functions sorted.
- Preserve the public API: function names, arities, argument order, defaults, and integer failure results (`-1`).
- Run `just sanitizers` (ASan/UBSan/LSan in Docker) after changing native code or templates.
- Use `sodium_memzero` for sensitive memory. States are NIF resources, one resource type per C struct; never modify a resource Erlang can see (copy, then return a new one). Validate with published vectors.
- Vendored libsodium is pinned in `c_src/Makefile` (`LIBSODIUM_VSN`); include native sources in package checks.
- Release version: `Makefile` and `src/libsodium.app.src`; update README and changelog together. Check `rebar3 hex build` contents.
- Make incremental signed commits (`git commit -S`).
