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
FEATURE_EXTRACTOR="${BOFUZZ_ROOT}/static_analysis/features_extractor.py"
FEATURE_SCHEMA="${BOFUZZ_ROOT}/static_analysis/features_schema.json"

HARNESS_CC="${SCRIPT_DIR}/zlib_uncompress_fuzzer.cc"
SEED_ZIP="${SCRIPT_DIR}/seed_corpus.zip"

ZLIB_GIT_URL="https://github.com/madler/zlib.git"
ZLIB_BRANCH="develop"
IDA_DIR="${IDA_DIR:-${HOME}/ida-pro-9.3}"
CREDIT_TOP_K="${CREDIT_TOP_K:-8}"

# =========================
# Checks
# =========================
die() { echo "[!] $*" >&2; exit 1; }

[[ -f "${STUB_RT_C}" ]]  || die "missing: ${STUB_RT_C}"
[[ -f "${HARNESS_CC}" ]] || die "missing: ${HARNESS_CC}"
[[ -f "${FEATURE_EXTRACTOR}" ]] || die "missing: ${FEATURE_EXTRACTOR}"
[[ -f "${FEATURE_SCHEMA}" ]] || die "missing: ${FEATURE_SCHEMA}"
[[ -d "${IDA_DIR}" ]] || die "IDA Pro not found at ${IDA_DIR}. Install IDA Pro 9.3 there, or set IDA_DIR=/path/to/ida-pro-9.3, then rerun."
if [[ ! -x "${IDA_DIR}/ida" && ! -x "${IDA_DIR}/idat" && ! -f "${IDA_DIR}/libidalib.so" ]]; then
  die "IDA Pro install at ${IDA_DIR} looks incomplete. Install IDA Pro 9.3 first, then rerun."
fi

command -v cargo >/dev/null 2>&1 || die "missing cmd: cargo"
command -v git >/dev/null 2>&1 || die "missing cmd: git"
command -v make >/dev/null 2>&1 || die "missing cmd: make"
command -v clang >/dev/null 2>&1 || die "missing cmd: clang"
command -v ar >/dev/null 2>&1 || die "missing cmd: ar"
command -v python3 >/dev/null 2>&1 || die "missing cmd: python3"
command -v unzip >/dev/null 2>&1 || echo "[*] unzip not found; will skip seed_corpus.zip extraction"

IDADIR="${IDA_DIR}" python3 -c 'import idapro' >/dev/null 2>&1 || die "Python cannot import 'idapro'. Run ${IDA_DIR}/idalib/python/py-activate-idalib.py once, then rerun."

# =========================
# Build latest BOFuzz engine
# =========================
echo "[*] building BOFuzz release engine ..."
pushd "${BOFUZZ_ROOT}/fuzzers/inprocess/bofuzz" >/dev/null
cargo build --profile release-bofuzz --features no_link_main
popd >/dev/null

[[ -x "${LIBAFL_CC}" ]]  || die "missing after BOFuzz build: ${LIBAFL_CC}"
[[ -x "${LIBAFL_CXX}" ]] || die "missing after BOFuzz build: ${LIBAFL_CXX}"

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

BIN="${OUT_DIR}/zlib_uncompress_fuzzer"
[[ -x "${BIN}" ]] || die "binary not found/executable: ${BIN}"
FEATURE_MAP="${OUT_DIR}/zlib_uncompress_fuzzer_features_map.json"

# =========================
# Extract static features
# =========================
echo "[*] extracting static features with IDA/IDALIB into: ${OUT_DIR}"
python3 "${FEATURE_EXTRACTOR}" \
  --idapro \
  --ida-dir "${IDA_DIR}" \
  --input-file "${BIN}" \
  --output-dir "${OUT_DIR}"

[[ -f "${FEATURE_MAP}" ]] || die "feature map not produced: ${FEATURE_MAP}"

# =========================
# Run
# =========================
export RUST_LOG="${RUST_LOG:-info}"

JEMALLOC_SO="/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"
if [[ -f "${JEMALLOC_SO}" ]]; then
  export LD_PRELOAD="${LD_PRELOAD:-${JEMALLOC_SO}}"
fi

DEFAULT_ARGS=(
  --features-schema "${FEATURE_SCHEMA}"
  --features-map "${FEATURE_MAP}"
  --vec-mask auto-credit
  --credit-top-k "${CREDIT_TOP_K}"
  --alpha 0.6
  --feat-mode 1
  --explore-time-secs 600
  --tpe-period-secs 300
  -i "${OUT_DIR}/corpus"
  -o "${OUT_DIR}/findings"
)

echo "[*] running: ${BIN} ${DEFAULT_ARGS[*]} $*"
exec "${BIN}" "${DEFAULT_ARGS[@]}" "$@"
