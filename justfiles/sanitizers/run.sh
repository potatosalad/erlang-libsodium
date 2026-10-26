#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/../..}" && pwd)"
c_src_dir="${project_root}/c_src"
dep_build="${project_root}/c_deps/libsodium-build-sanitizers"
restore_build="${SANITIZERS_RESTORE_BUILD:-1}"
stress_iterations="${SANITIZERS_STRESS_ITERATIONS:-10000}"
jobs="${SANITIZERS_JOBS:-4}"
color="${SANITIZERS_COLOR:-always}"
upstream_tests="${SANITIZERS_UPSTREAM_TESTS:-1}"
suites="${SANITIZERS_CT_SUITES:-}"
if [[ -z "${suites}" ]]; then
    # Discover every maintained suite; new suites automatically get instrumented.
    for suite_path in "${project_root}"/test/*_SUITE.erl; do
        suite_name="${suite_path##*/}"
        suites+="${suite_name%_SUITE.erl} "
    done
    suites="${suites% }"
fi
make_cmd="${MAKE:-make}"

case "${restore_build}" in 0 | 1) ;; *) echo 'SANITIZERS_RESTORE_BUILD must be 0 or 1' >&2; exit 2 ;; esac
case "${upstream_tests}" in 0 | 1) ;; *) echo 'SANITIZERS_UPSTREAM_TESTS must be 0 or 1' >&2; exit 2 ;; esac
case "${color}" in auto | always | never) ;; *) echo 'SANITIZERS_COLOR must be auto, always, or never' >&2; exit 2 ;; esac
if [[ ! "${stress_iterations}" =~ ^[1-9][0-9]*$ || ! "${jobs}" =~ ^[1-9][0-9]*$ ]]; then
    echo 'SANITIZERS_STRESS_ITERATIONS and SANITIZERS_JOBS must be positive integers' >&2
    exit 2
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "the native runner requires Linux; use 'just sanitizers-docker'" >&2
    exit 1
fi
for tool in "${make_cmd}" clang llvm-nm erl erlc; do
    command -v "${tool}" >/dev/null || { echo "missing tool: ${tool}" >&2; exit 1; }
done
emu_type="$({ ASAN_OPTIONS=detect_leaks=0 erl -emu_type asan -noshell \
    -eval 'io:put_chars(atom_to_list(erlang:system_info(emu_type))), halt().' ; } 2>/dev/null || true)"
if [[ "${emu_type}" != asan ]]; then
    echo "an Erlang/OTP ASan emulator is required; use 'just sanitizers-docker'" >&2
    exit 1
fi

report_root="${SANITIZERS_REPORT_DIR:-${project_root}/logs/sanitizers}"
mkdir -p "${report_root}"
report_dir="$(mktemp -d "${report_root}/run-XXXXXXXX")"
tmp_dir="$(mktemp -d)"
build_started=0
finish() {
    local status=$?
    local report
    trap - EXIT
    set +e
    for report in "${report_dir}"/asan-* "${report_dir}"/ubsan-*; do
        if [[ -s "${report}" ]]; then
            printf '\n[sanitizers] report: %s\n' "${report}"
            cat "${report}"
            if [[ ${status} -eq 0 ]]; then status=1; fi
        fi
    done
    if [[ ${build_started} -eq 1 && "${restore_build}" == 1 ]]; then
        echo '[sanitizers] restoring the normal NIF build'
        "${make_cmd}" -C "${c_src_dir}" clean CC=clang &&
            "${make_cmd}" -C "${c_src_dir}" -j"${jobs}" SANITIZE=0 CC=clang
        local restored=$?
        if [[ ${status} -eq 0 && ${restored} -ne 0 ]]; then status=${restored}; fi
    fi
    rm -rf "${tmp_dir}"
    echo "[sanitizers] logs: ${report_dir}"
    if [[ ${status} -eq 0 ]]; then echo '[sanitizers] no ASan, LSan, or UBSan findings'; fi
    exit "${status}"
}
trap finish EXIT

lsan_options='print_suppressions=0:exitcode=23'
if [[ -n "${SANITIZERS_LSAN_SUPPRESSIONS:-}" ]]; then
    test -f "${SANITIZERS_LSAN_SUPPRESSIONS}"
    lsan_options="suppressions=${SANITIZERS_LSAN_SUPPRESSIONS}:print_suppressions=0:exitcode=23"
fi
sanitizer_env=(env
    "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1:color=${color}:log_path=${report_dir}/asan-libsodium"
    "LSAN_OPTIONS=${lsan_options}"
    "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:color=${color}:log_path=${report_dir}/ubsan-libsodium"
)
if symbolizer="$(command -v llvm-symbolizer || true)" && [[ -n "${symbolizer}" ]]; then
    sanitizer_env+=("ASAN_SYMBOLIZER_PATH=${symbolizer}")
fi
# The ASan emulator provides the ASan runtime; the NIF must bring UBSan's.
ubsan_lib="$(clang -print-file-name="libclang_rt.ubsan_standalone-$(uname -m).so")"
if [[ ! -f "${ubsan_lib}" ]]; then
    echo "missing Clang UBSan runtime: ${ubsan_lib}" >&2
    exit 1
fi
make_args=(SANITIZE=1 CC=clang
    "LIBSODIUM_BUILD_DIR=${dep_build}"
    "LDFLAGS_SANITIZE=-fsanitize=address ${ubsan_lib} -Wl,-rpath,$(dirname "${ubsan_lib}")"
)
echo '[sanitizers] building libsodium and the NIF with ASan/UBSan'
build_started=1
"${make_cmd}" -C "${c_src_dir}" clean "${make_args[@]}"
# Reconfigure even when a previous sanitizer run used different compiler flags.
rm -f "${dep_build}/Makefile"
"${sanitizer_env[@]}" "${make_cmd}" -C "${c_src_dir}" -j"${jobs}" "${make_args[@]}" 2>&1 | tee "${report_dir}/build.log"

# A successful build must actually instrument both sides of the NIF boundary.
for binary in "${dep_build}/prefix/lib/libsodium.a" "${project_root}/priv/libsodium_nif.so"; do
    llvm-nm --undefined-only "${binary}" > "${tmp_dir}/symbols" 2>/dev/null
    grep -q '__asan_' "${tmp_dir}/symbols"
    grep -q '__ubsan_' "${tmp_dir}/symbols"
    echo "[sanitizers] verified ASan/UBSan instrumentation: ${binary}"
done

if [[ "${upstream_tests}" == 1 ]]; then
    echo "[sanitizers] running libsodium's own test suite"
    "${sanitizer_env[@]}" "${make_cmd}" -C "${dep_build}" -j"${jobs}" check 2>&1 | tee "${report_dir}/upstream.log"
fi

erl_aflags="${ERL_AFLAGS:+${ERL_AFLAGS} }-emu_type asan"
echo "[sanitizers] running Common Test: ${suites}"
(
    cd "${project_root}"
    "${sanitizer_env[@]}" "ERL_AFLAGS=${erl_aflags}" \
        "${make_cmd}" tests "CT_SUITES=${suites}" "${make_args[@]}"
) 2>&1 | tee "${report_dir}/ct.log"

"${sanitizer_env[@]}" "ERL_AFLAGS=${erl_aflags}" \
    erlc +debug_info -o "${tmp_dir}" "${project_root}/justfiles/sanitizers/libsodium_sanitizer_stress.erl"
echo "[sanitizers] resource/error cleanup stress: ${stress_iterations} iterations"
"${sanitizer_env[@]}" erl -emu_type asan -noshell -pa "${project_root}/ebin" "${tmp_dir}" \
    -eval 'libsodium_sanitizer_stress:run(list_to_integer(hd(init:get_plain_arguments()))), halt().' \
    -extra "${stress_iterations}" 2>&1 | tee "${report_dir}/stress.log"
