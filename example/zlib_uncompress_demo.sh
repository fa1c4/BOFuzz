#!/usr/bin/env bash
set -euo pipefail

# =========================
# Paths (relative, robust)
# =========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOFUZZ_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKDIR="${SCRIPT_DIR}/work"
ZLIB_DIR="${WORKDIR}/zlib"
OUT_DIR="${ZLIB_DIR}/out"

BOFUZZ_BIN_DIR="${BOFUZZ_ROOT}/fuzzers/inprocess/bofuzz/target/release-bofuzz"
LIBAFL_CC="${BOFUZZ_BIN_DIR}/libafl_cc"
LIBAFL_CXX="${BOFUZZ_BIN_DIR}/libafl_cxx"
STUB_RT_C="${BOFUZZ_ROOT}/fuzzers/inprocess/bofuzz/stub_rt.c"

HARNESS_CC="${SCRIPT_DIR}/zlib_uncompress_fuzzer.cc"
SEED_ZIP="${SCRIPT_DIR}/seed_corpus.zip"

ZLIB_GIT_URL="https://github.com/madler/zlib.git"
ZLIB_BRANCH="develop"

# =========================
# Checks
# =========================
die() { echo "[!] $*" >&2; exit 1; }

[[ -x "${LIBAFL_CC}" ]]  || die "missing: ${LIBAFL_CC} (did you build bofuzz release?)"
[[ -x "${LIBAFL_CXX}" ]] || die "missing: ${LIBAFL_CXX} (did you build bofuzz release?)"
[[ -f "${STUB_RT_C}" ]]  || die "missing: ${STUB_RT_C}"
[[ -f "${HARNESS_CC}" ]] || die "missing: ${HARNESS_CC}"

command -v git >/dev/null 2>&1 || die "missing cmd: git"
command -v make >/dev/null 2>&1 || die "missing cmd: make"
command -v unzip >/dev/null 2>&1 || echo "[*] unzip not found; will skip seed_corpus.zip extraction"

# =========================
# Clean & fetch zlib
# =========================
mkdir -p "${WORKDIR}"
rm -rf "${ZLIB_DIR}"
echo "[*] cloning zlib (${ZLIB_BRANCH}) into: ${ZLIB_DIR}"
git clone --depth 1 -b "${ZLIB_BRANCH}" "${ZLIB_GIT_URL}" "${ZLIB_DIR}"

mkdir -p "${OUT_DIR}"

# =========================
# Build stub runtime from source
# =========================
STUB_RT_A="${WORKDIR}/stub_rt.a"
echo "[*] building stub_rt.a from ${STUB_RT_C} ..."
clang -c "${STUB_RT_C}" -o "${WORKDIR}/stub_rt.o"
ar r "${STUB_RT_A}" "${WORKDIR}/stub_rt.o"

# =========================
# Toolchain env (LibAFL CC/CXX + stub runtime)
# =========================
export SRC="${ZLIB_DIR}"
export OUT="${OUT_DIR}"

export CC="${LIBAFL_CC}"
export CXX="${LIBAFL_CXX}"

export FUZZER_LIB="${STUB_RT_A}"
export LIB_FUZZING_ENGINE="${FUZZER_LIB}"

export CFLAGS="--libafl -g -O3 -fsanitize-coverage=trace-pc-guard,trace-cmp,inline-8bit-counters,pc-table"
export CXXFLAGS="--libafl --std=c++14 -g -O3 -fsanitize-coverage=trace-pc-guard,trace-cmp,inline-8bit-counters,pc-table"
export LDFLAGS="--libafl -fsanitize-coverage=trace-pc-guard,trace-cmp,inline-8bit-counters,pc-table"

export ASAN_OPTIONS="abort_on_error=0:allocator_may_return_null=1"
export UBSAN_OPTIONS="abort_on_error=0"

# =========================
# Build zlib (instrumented)
# =========================
pushd "${ZLIB_DIR}" >/dev/null

echo "[*] building zlib (instrumented) ..."
make distclean >/dev/null 2>&1 || true
./configure --static
make -j"$(nproc)"

# =========================
# Build fuzzer target (harness + libz.a + stub_rt.a)
# =========================
echo "[*] building target binary into: ${OUT_DIR}"
"${CXX}" ${CXXFLAGS} -I. \
  "${HARNESS_CC}" \
  "${ZLIB_DIR}/libz.a" \
  "${LIB_FUZZING_ENGINE}" \
  -pthread \
  -o "${OUT_DIR}/zlib_uncompress_fuzzer"

popd >/dev/null

# =========================
# Prepare out dir: corpus/findings
# =========================
mkdir -p "${OUT_DIR}/corpus" "${OUT_DIR}/findings"

if [[ -f "${SEED_ZIP}" ]] && command -v unzip >/dev/null 2>&1; then
  echo "[*] extracting seed corpus zip into: ${OUT_DIR}/corpus"
  unzip -o "${SEED_ZIP}" -d "${OUT_DIR}/corpus" >/dev/null
else
  echo "[*] seed_corpus.zip not found (or unzip missing). You can put seeds into: ${OUT_DIR}/corpus"
fi

# =========================
# Run
# =========================
export RUST_LOG="${RUST_LOG:-info}"

JEMALLOC_SO="/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"
if [[ -f "${JEMALLOC_SO}" ]]; then
  export LD_PRELOAD="${LD_PRELOAD:-${JEMALLOC_SO}}"
fi

BIN="${OUT_DIR}/zlib_uncompress_fuzzer"
[[ -x "${BIN}" ]] || die "binary not found/executable: ${BIN}"

DEFAULT_ARGS=(
  --features-schema "${BOFUZZ_ROOT}/static_analysis/features_schema.json"
  --alpha 0.6
  --feat-mode 1
  --explore-time-secs 43200
  --tpe-period-secs 600
  -i "${OUT_DIR}/corpus"
  -o "${OUT_DIR}/findings"
)

echo "[*] running: ${BIN} ${DEFAULT_ARGS[*]} $*"
exec "${BIN}" "${DEFAULT_ARGS[@]}" "$@"
