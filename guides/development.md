# Development

Building needs a C compiler, `make` (GNU Make 4 or later for the top-level
Makefile, invoked as `gmake` on macOS), and Erlang/OTP 27 or later. Rebar3 3.28.0
or later is required for the development tools and Hex publishing. Elixir is
needed only for the benchmark scripts. Python 3.13+, Poetry, and `just` are
needed when changing generated code.

## Build and test

```sh
gmake
gmake tests
gmake ct CT_SUITES='libsodium scheduling'
gmake format
gmake lint
```

The first build compiles the vendored libsodium out of tree into
`c_deps/libsodium-build`. `gmake lint` checks C and Erlang formatting, eqWAlizer,
cross references, and Dialyzer; ELP and erlfmt are downloaded at pinned versions
on first use. Common Test writes `logs/junit_report.xml`, and failed tests or
failed setup and cleanup callbacks fail the test command.

The suites are:

- `libsodium_api_SUITE`, generated from the namespace definitions: recorded
  constants, each module's documented example, and the extra cases in each
  definition.
- `libsodium_SUITE`: libsodium's published vectors for AEADs, sealed boxes,
  password hashing, and Ed25519, plus state resource behaviour.
- `scheduling_SUITE`: with one scheduler online, checks that large calls move to
  dirty schedulers and that streaming updates yield.

GitHub CI builds and tests the latest OTP 28 and 29 releases. OTP 29 also runs
the lint targets, builds ExDoc, and checks the Hex package. A separate job checks
Python formatting, the generator tests, and that `README.md` is current.

The upstream C source is vendored under `c_deps/libsodium` and pinned in
`c_src/Makefile` (`LIBSODIUM_VSN`). If removed, it is cloned at that tag. The
vendored copy is a git checkout without libsodium's generated `configure`
script, so building from this repository also needs autoconf, automake, and
libtool; the first build runs `autogen.sh`. Hex packages include the generated
script, so their users need only a C compiler and `make`.

## Code generation

The NIF sources, every Erlang module, `libsodium_api_SUITE`, `ex_doc.config`,
and `README.md` are generated, and carry a signature marker at the top. Change the
definitions in `codegen/namespaces/` or the templates, then regenerate and commit
the inputs and outputs together:

```sh
just codegen          # or: just docker-codegen
cd codegen
poetry run pytest
```

See the [codegen workflow](https://github.com/potatosalad/erlang-libsodium/blob/3.0.1/codegen/README.md)
for the definition format, Erlang types, scheduling, and dependency locking.

## Sanitizers

```sh
just sanitizers
SANITIZERS_STRESS_ITERATIONS=50000 just sanitizers
```

The Docker runner builds an Erlang/OTP ASan emulator, instruments libsodium and
the NIF with AddressSanitizer and UndefinedBehaviorSanitizer, and runs libsodium's
own test suite, every Common Test suite, and a stress test of state resources,
cancelled yielding updates, and error paths, with LeakSanitizer enabled. Reports
are kept under `logs/sanitizers/`. Set `SANITIZERS_UPSTREAM_TESTS=0` to skip
libsodium's tests. On Linux with an ASan-enabled OTP installation, use
`just sanitizers-native`.

## Benchmarks

```sh
just bench
just bench aead
```

The scripts under `bench/` compare libsodium's implementations with each other
and with Erlang/OTP `crypto`. See [bench/README.md](https://github.com/potatosalad/erlang-libsodium/blob/3.0.1/bench/README.md).

## Documentation and packages

```sh
gmake docs
rebar3 hex build
```

Open `doc/index.html`. The README, this guide, the migration guide, the
changelog, and the license are included, and source links target the release
tag. The package includes the native sources, the vendored libsodium, and the
guides; build it locally to check its contents before publishing.

## Releasing

Set the version in `Makefile` (`PROJECT_VERSION`) and `src/libsodium.app.src`,
date the changelog entry, update the versioned links in this guide, and run
`just codegen` to update `README.md` and `ex_doc.config`. After CI passes on
`main`, create a signed tag and publish:

```sh
git tag -s 3.0.1 -m "Version 3.0.1"
git push origin 3.0.1
rebar3 hex publish
```
