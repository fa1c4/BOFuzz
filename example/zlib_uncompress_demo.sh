#!/usr/bin/env bash
set -euo pipefail

# =========================
# Paths (relative, robust)
# =========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUNAFL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKDIR="${SCRIPT_DIR}/work"
ZLIB_DIR="${WORKDIR}/zlib"
OUT_DIR="${ZLIB_DIR}/out"

LIBFUN_BIN_DIR="${FUNAFL_ROOT}/fuzzers/inprocess/libfun/target/release-libfun"
LIBAFL_CC="${LIBFUN_BIN_DIR}/libafl_cc"
LIBAFL_CXX="${LIBFUN_BIN_DIR}/libafl_cxx"
STUB_RT_A="${FUNAFL_ROOT}/fuzzers/inprocess/libfun/stub_rt.a"

HARNESS_CC="${SCRIPT_DIR}/zlib_uncompress_fuzzer.cc"
FEATURES_MAP="${SCRIPT_DIR}/zlib_uncompress_fuzzer_features_map.json"
SEED_ZIP="${SCRIPT_DIR}/seed_corpus.zip"

ZLIB_GIT_URL="https://github.com/madler/zlib.git"
ZLIB_BRANCH="develop"

# =========================
# Checks
# =========================
die() { echo "[!] $*" >&2; exit 1; }

[[ -x "${LIBAFL_CC}" ]]  || die "missing: ${LIBAFL_CC} (did you build libfun release?)"
[[ -x "${LIBAFL_CXX}" ]] || die "missing: ${LIBAFL_CXX} (did you build libfun release?)"
[[ -f "${STUB_RT_A}" ]]  || die "missing: ${STUB_RT_A}"
[[ -f "${HARNESS_CC}" ]] || die "missing: ${HARNESS_CC}"
[[ -f "${FEATURES_MAP}" ]] || die "missing: ${FEATURES_MAP}"

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
# Prepare out dir: corpus/findings + copy maps
# =========================
mkdir -p "${OUT_DIR}/corpus" "${OUT_DIR}/findings"

echo "[*] copying features_map into out dir (same dir as binary) ..."
cp -f "${FEATURES_MAP}" "${OUT_DIR}/"

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

DEFAULT_ARGS=(--alpha 0.6 --feat-mode 2 --explore-time 3600 --tpe-period 600 -i "${OUT_DIR}/corpus" -o "${OUT_DIR}/findings")

echo "[*] running: ${BIN} ${DEFAULT_ARGS[*]} $*"
exec "${BIN}" "${DEFAULT_ARGS[@]}" "$@"
