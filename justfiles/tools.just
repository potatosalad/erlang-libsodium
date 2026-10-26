[working-directory: 'codegen']
codegen: poetry-install
    poetry run erlang_libsodium_codegen json-schema schema.json
    poetry run erlang_libsodium_codegen generate config.yaml .. templates0 templates1
    just format-c-targets
    gmake -C .. erlfmt
    gmake -C ..
    poetry run erlang_libsodium_codegen generate --stage docs config.yaml .. templates0 templates1 templates2
    just sign

format: poetry-install format-c-targets format-c-templates format-python-src
    gmake format

[working-directory: 'codegen']
format-c-targets:
    #!/usr/bin/env bash
    set -euo pipefail
    poetry run clang-format --version
    find ../c_src \( -type l -o -type f \) \( -name '*.c' -o -name '*.C' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.c.h' -o -name '*.hpp' \) -print0 | \
        xargs -0 poetry run clang-format --style="file:../c_src/.clang-format" -i

[working-directory: 'codegen']
format-c-templates:
    #!/usr/bin/env bash
    set -euo pipefail
    poetry run clang-format --version
    find templates0 templates1 \( -type l -o -type f \) \( -name '*.c.j2' -o -name '*.C.j2' -o -name '*.cc.j2' -o -name '*.cpp.j2' -o -name '*.h.j2' -o -name '*.c.h.j2' -o -name '*.hpp.j2' \) -print0 | \
        xargs -0 poetry run clang-format --style="file:../c_src/.clang-format" -i

[working-directory: 'codegen']
format-python-src:
    poetry run black src/ tests/

lock:
    just poetry-lock

[working-directory: 'codegen']
sign: poetry-install
    poetry run erlang_libsodium_codegen sign config.yaml .. templates0 templates1 templates2
