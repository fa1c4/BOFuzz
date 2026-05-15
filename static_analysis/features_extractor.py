# -*- coding: utf-8 -*-
"""
Build {binary}_features_map.json aligned to sancov pc-table,
USING ONLY the target-binary-exclusive CFG/CG (reachable from LLVMFuzzerTestOneInput).

Canonical 16-feature basic-block static extractor (schema v3).

No external deps. Designed for IDA Pro. Supports two execution modes:

  Mode A: Traditional IDA internal execution
    /path/to/idat64 -A -Sstatic_analysis/features_extractor.py <binary>

  Mode B: PyPI ``idapro`` / IDALIB external Python execution
    python3 static_analysis/features_extractor.py --idapro \
        --input-file <binary> --ida-dir <ida_install_dir>

Top-level imports are restricted to the Python standard library so that
``python3 static_analysis/features_extractor.py --help`` works outside IDA
without importing ``idaapi``.

USAGE:
cd ~/BOFuzz
# Acceptance #1 — outside-IDA --help
python3 static_analysis/features_extractor.py --help

# Acceptance #2 + #8/#9 — Mode B with --output-dir
python3 static_analysis/features_extractor.py --idapro --ida-dir /data/zym/ida-pro-9.3 \
  --input-file benchs/lcms/cms_transform_fuzzer --output-dir /tmp/cms_features
#  -> 20 files in /tmp/cms_features/
#  -> merged map has 16 keys, every array length 7713 (matches collected PCs)
#  -> schema execution.mode == "idapro"

# Default-dir variant — outputs go to benchs/lcms/
python3 static_analysis/features_extractor.py --idapro --ida-dir /data/zym/ida-pro-9.3 \
  --input-file benchs/lcms/cms_transform_fuzzer
#  -> outputs land in /data/zym/BOFuzz/benchs/lcms/
"""

import argparse
import os
import sys
import json
import math
import time
import logging
from collections import defaultdict, deque

# ============================ IDA MODULES ============================
# These are populated lazily by import_ida_modules() once we know whether
# we are running inside IDA (Mode A) or under PyPI idapro / IDALIB (Mode B).
idaapi = None
idc = None
ida_bytes = None
ida_nalt = None
ida_segment = None
idautils = None
ida_auto = None

# Execution-state globals.
_IDAPRO_LIB = None
_IDAPRO_DB_OPENED = False
_IDAPRO_CLOSE_SAVE = False
_RUNNING_UNDER_IDAPRO = False
_RUNNING_INSIDE_IDA = False

# Lazily populated set of operand types treated as referenceable; filled in
# by import_ida_modules() because it depends on idaapi constants.
_REF_OPERAND_TYPES = None


def import_ida_modules():
    """Import IDA Python modules and stash them in module globals.

    Also initialises ``_REF_OPERAND_TYPES`` which depends on idaapi constants.
    Safe to call multiple times; later calls just re-bind the same modules.

    Note: ``import idapro`` (PyPI IDALIB) has the side-effect of dumping many
    IDA names (including the ``idaapi`` / ``idc`` / ``ida_auto`` / ``ida_bytes``
    / ``ida_nalt`` / ``ida_segment`` modules) directly into our module's
    globals, but it does NOT export ``idautils``. So we cannot use the state
    of these globals as a "have we imported yet?" guard.
    """
    global idaapi, idc, ida_bytes, ida_nalt, ida_segment, idautils, ida_auto
    global _REF_OPERAND_TYPES

    import idaapi as _idaapi
    import idc as _idc
    import ida_bytes as _ida_bytes
    import ida_nalt as _ida_nalt
    import ida_segment as _ida_segment
    import idautils as _idautils
    import ida_auto as _ida_auto

    idaapi = _idaapi
    idc = _idc
    ida_bytes = _ida_bytes
    ida_nalt = _ida_nalt
    ida_segment = _ida_segment
    idautils = _idautils
    ida_auto = _ida_auto

    _REF_OPERAND_TYPES = {
        idaapi.o_imm,
        idaapi.o_mem,
        idaapi.o_displ,
        idaapi.o_near,
        idaapi.o_far,
    }


# ============================= CONFIG =============================
SEED_ENTRY_NAMES = [
    "LLVMFuzzerTestOneInput",
]
EPS_NON_TARGET = 1e-9
VERBOSE = True

log = logging.getLogger("target_features_map")
if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ---- Schema v3: canonical 16-dim feature set ----
FEATURE_SCHEMA_VERSION = 3

ATTR_NAMES = [
    # Instruction-level BB features
    "bb_instruction_count",
    "numeric_immediate_count",
    "string_literal_ref_count",
    "const_data_ref_count",
    "cmp_inst_count",
    "arith_bitwise_count",
    "mem_inst_count",
    "call_count",
    # Structural-level BB features
    "cfg_in_degree",
    "cfg_out_degree",
    "static_descendant_count",
    "static_ancestor_count",
    "entry_depth",
    "loop_nesting_depth",
    "loop_boundary_flag",
    "centrality",
]

INSTRUCTION_ATTRS = ATTR_NAMES[:8]
STRUCTURAL_ATTRS = ATTR_NAMES[8:]

# ---- APageRank (disabled by default) ----
USE_APAGERANK = False
APAGERANK_DAMPING = 0.85
APAGERANK_GAMMA = 1.0
APAGERANK_TAU = 1.0
APAGERANK_EPSILON = 0.01
APAGERANK_ITER_MAX = 5

# ---- Centrality ----
CENTRALITY_EXACT_MAX = 3000
CENTRALITY_SAMPLE_MAX = 3000
CENTRALITY_SAMPLE_SEED = 0xC0FFEE

# ---- Immediate filtering ----
FILTER_TRIVIAL_IMMEDIATES = True
TRIVIAL_IMMEDIATE_VALUES = {
    0, 1, 2, 4, 8, 16, 32, 64,
    255, 256, 512, 1024,
}

# ---- Const-data segments (normalized to lowercase at definition) ----
CONST_DATA_SEGMENT_NAMES = {x.lower() for x in {
    ".rodata",
    ".rdata",
    "__const",
    "__cstring",
    ".const",
    ".data.rel.ro",
}}

# ---- String detection ----
STRICT_STRING_DETECTION = True

STRING_SEGMENT_NAMES = {
    "__cstring",
}

# ---- Normalization groups ----
LOG1P_FEATURES = {
    "static_descendant_count",
    "static_ancestor_count",
    "entry_depth",
    "centrality",
}

RAW_BINARY_FEATURES = {
    "loop_boundary_flag",
}

# ---- Instruction mnemonic sets ----
STRING_MEMORY_MNEMS = {
    "movs", "movsb", "movsw", "movsd", "movsq",
    "stos", "stosb", "stosw", "stosd", "stosq",
    "lods", "lodsb", "lodsw", "lodsd", "lodsq",
    "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
    "scas", "scasb", "scasw", "scasd", "scasq",
}

STRING_CMP_MNEMS = {
    "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
    "scas", "scasb", "scasw", "scasd", "scasq",
}

# ======================= CORE UTILITIES =======================
def get_seg_bounds(seg_name):
    seg = ida_segment.get_segm_by_name(seg_name)
    if seg:
        return seg.start_ea, seg.end_ea
    try:
        ea = idc.get_segm_by_name(seg_name)
        if ea != idc.BADADDR:
            seg = idaapi.getseg(ea)
            if seg:
                return seg.start_ea, seg.end_ea
    except Exception:
        pass
    return None, None

def read_qword_safe(ea):
    try:
        return ida_bytes.get_qword(ea)
    except Exception:
        return None

def is_plausible_code_addr(addr):
    if addr is None or addr in (0, idc.BADADDR):
        return False
    seg = idaapi.getseg(addr)
    if not seg:
        return False
    name = idaapi.get_segm_name(seg) or ""
    return name.lower() in ('.text', 'text', 'code', '__text')

def get_base_mnemonic(addr):
    m = (idc.print_insn_mnem(addr) or '').lower()
    for p in ('rep ', 'repe ', 'repz ', 'repne ', 'repnz ', 'lock '):
        if m.startswith(p):
            return m[len(p):]
    return m

def finite_or_zero(x):
    if math.isnan(x) or math.isinf(x):
        return 0.0
    return float(x)

def get_arch_bits():
    try:
        inf = idaapi.get_inf_structure()
        if inf.is_64bit():
            return 64
        if inf.is_32bit():
            return 32
    except Exception:
        pass
    return 64

def to_signed_imm(v, bits=None):
    if bits is None:
        bits = get_arch_bits()
    mask = (1 << bits) - 1
    v = int(v) & mask
    sign = 1 << (bits - 1)
    if v & sign:
        return v - (1 << bits)
    return v

# ======================= STRING TABLE =======================
def get_all_ida_strings():
    addrs = set()
    try:
        for s in idautils.Strings():
            if hasattr(s, "ea"):
                addrs.add(s.ea)
            else:
                addrs.add(int(s))
    except Exception:
        pass
    return addrs

def get_string_at_address(addr):
    try:
        st = idc.get_str_type(addr)
        if st != -1:
            try:
                return idc.get_strlit_contents(addr).decode('utf-8', errors='ignore')
            except Exception:
                pass
        data = idc.get_bytes(addr, 512)
        if not data:
            return None
        p = data.find(b'\x00')
        if p > 0:
            try:
                return data[:p].decode('utf-8', errors='ignore')
            except Exception:
                try:
                    return data[:p].decode('ascii', errors='ignore')
                except Exception:
                    pass
        try:
            wide = data[::2]
            p2 = wide.find(b'\x00')
            if p2 > 0:
                return wide[:p2].decode('ascii', errors='ignore')
        except Exception:
            pass
        return None
    except Exception:
        return None

def looks_like_printable_c_string(addr, max_len=256):
    data = idc.get_bytes(addr, max_len)
    if not data:
        return False
    nul = data.find(b"\x00")
    if nul < 2:
        return False
    s = data[:nul]
    printable = 0
    for c in s:
        if c in (9, 10, 13) or 32 <= c <= 126:
            printable += 1
    return float(printable) / float(len(s)) >= 0.85

# ======================= OPERAND / REFERENCE CLASSIFICATION =======================
def get_segment_name(ea):
    seg = idaapi.getseg(ea)
    if seg:
        return (idaapi.get_segm_name(seg) or "").strip()
    return ""

def canonical_seg_name(addr):
    name = get_segment_name(addr)
    return (name or "").lower()

def is_text_addr(addr):
    name = canonical_seg_name(addr)
    return name in ('.text', 'text', 'code', '__text')

def is_const_data_addr(addr):
    if addr is None or addr in (0, idc.BADADDR):
        return False
    seg_name = canonical_seg_name(addr)
    return seg_name in CONST_DATA_SEGMENT_NAMES

def is_string_addr(addr, string_addrs):
    if addr is None or addr in (0, idc.BADADDR):
        return False

    if addr in string_addrs:
        return True

    try:
        st = idc.get_str_type(addr)
        if st != -1:
            return True
    except Exception:
        pass

    seg_name = canonical_seg_name(addr)
    if seg_name in STRING_SEGMENT_NAMES:
        return looks_like_printable_c_string(addr)

    if STRICT_STRING_DETECTION:
        return False

    return get_string_at_address(addr) is not None

def classify_operand_value(value, string_addrs):
    """
    Return one of:
      "string_ref", "const_data_ref", "code_ref",
      "address_ref", "numeric_immediate", "unknown"
    """
    if value is None or value in (idc.BADADDR,):
        return "unknown"

    if value == 0:
        return "numeric_immediate"

    seg = idaapi.getseg(value)
    if not seg:
        return "numeric_immediate"

    if is_string_addr(value, string_addrs):
        return "string_ref"

    if is_const_data_addr(value):
        return "const_data_ref"

    if is_plausible_code_addr(value):
        return "code_ref"

    return "address_ref"

def is_trivial_immediate(v):
    try:
        uv = int(v)
        sv = to_signed_imm(uv)

        if uv in TRIVIAL_IMMEDIATE_VALUES:
            return True

        if sv in TRIVIAL_IMMEDIATE_VALUES:
            return True

        if -256 <= sv < 0:
            return True

        return False
    except Exception:
        return False

# ======================= INSTRUCTION CLASSIFIERS =======================
def is_cmp_inst(mnem):
    if mnem in {"cmp", "test"}:
        return True
    if mnem in {"cmpxchg", "cmpxchg8b", "cmpxchg16b"}:
        return True
    if mnem in STRING_CMP_MNEMS:
        return True
    if mnem.startswith("ucomis"):
        return True
    if mnem.startswith("comis"):
        return True
    if mnem.startswith("pcmp"):
        return True
    if mnem.startswith("vpcmp"):
        return True
    if mnem.startswith("fcom"):
        return True
    if mnem == "ftst":
        return True
    return False

_ARITH_BASIC = {
    'add', 'adc', 'sub', 'sbb', 'mul', 'imul', 'div', 'idiv',
    'inc', 'dec', 'neg', 'abs',
}
_ARITH_BITLOG = {
    'and', 'or', 'xor', 'not',
    'bt', 'btc', 'btr', 'bts',
    'bsf', 'bsr', 'popcnt', 'lzcnt', 'tzcnt', 'andn',
}
_ARITH_SHIFT = {
    'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr',
    'shld', 'shrd', 'shrx', 'shlx', 'sarx',
}
_ARITH_X87 = {
    'fadd', 'faddp', 'fiadd', 'fsub', 'fsubp', 'fisub',
    'fsubr', 'fsubrp', 'fisubr', 'fmul', 'fmulp', 'fimul',
    'fdiv', 'fdivp', 'fidiv', 'fdivr', 'fdivrp', 'fidivr',
    'fabs', 'fchs', 'fsqrt', 'fsin', 'fcos', 'fsincos',
    'fptan', 'fpatan', 'f2xm1', 'fyl2x', 'fyl2xp1',
    'fscale', 'frndint', 'fxtract', 'fprem', 'fprem1',
    'fxam',
}
_ARITH_SSE_SCALAR = {
    'addss', 'addsd', 'subss', 'subsd', 'mulss', 'mulsd', 'divss', 'divsd',
    'sqrtss', 'sqrtsd', 'rsqrtss', 'rcpss',
    'minss', 'minsd', 'maxss', 'maxsd',
}
_ARITH_SSE_PACKED = {
    'addps', 'addpd', 'subps', 'subpd', 'mulps', 'mulpd', 'divps', 'divpd',
    'sqrtps', 'sqrtpd', 'rsqrtps', 'rcpps',
    'minps', 'minpd', 'maxps', 'maxpd',
    'dpps', 'dppd',
}
_ARITH_SSE_INT = {
    'paddb', 'paddw', 'paddd', 'paddq', 'paddsb', 'paddsw', 'paddusb', 'paddusw',
    'psubb', 'psubw', 'psubd', 'psubq', 'psubsb', 'psubsw', 'psubusb', 'psubusw',
    'pmullw', 'pmulhw', 'pmulhuw', 'pmulld', 'pmuludq', 'pmuldq',
    'pmaxsb', 'pmaxsw', 'pmaxsd', 'pmaxub', 'pmaxuw', 'pmaxud',
    'pminsb', 'pminsw', 'pminsd', 'pminub', 'pminuw', 'pminud',
    'pabsb', 'pabsw', 'pabsd', 'psadbw', 'pavgb', 'pavgw',
}
_ARITH_AVX = {
    'vaddss', 'vaddsd', 'vaddps', 'vaddpd', 'vsubss', 'vsubsd', 'vsubps', 'vsubpd',
    'vmulss', 'vmulsd', 'vmulps', 'vmulpd', 'vdivss', 'vdivsd', 'vdivps', 'vdivpd',
    'vsqrtss', 'vsqrtsd', 'vsqrtps', 'vsqrtpd', 'vrsqrtss', 'vrsqrtps', 'vrcpss', 'vrcpps',
    'vminss', 'vminsd', 'vminps', 'vminpd', 'vmaxss', 'vmaxsd', 'vmaxps', 'vmaxpd',
    'vpaddb', 'vpaddw', 'vpaddd', 'vpaddq', 'vpaddsb', 'vpaddsw', 'vpaddusb', 'vpaddusw',
    'vpsubb', 'vpsubw', 'vpsubd', 'vpsubq', 'vpsubsb', 'vpsubsw', 'vpsubusb', 'vpsubusw',
    'vpmullw', 'vpmulhw', 'vpmulhuw', 'vpmulld', 'vpmuludq', 'vpmuldq',
}
_ARITH_FMA = {
    'vfmadd132ps', 'vfmadd132pd', 'vfmadd132ss', 'vfmadd132sd',
    'vfmadd213ps', 'vfmadd213pd', 'vfmadd213ss', 'vfmadd213sd',
    'vfmadd231ps', 'vfmadd231pd', 'vfmadd231ss', 'vfmadd231sd',
    'vfmsub132ps', 'vfmsub132pd', 'vfmsub132ss', 'vfmsub132sd',
    'vfmsub213ps', 'vfmsub213pd', 'vfmsub213ss', 'vfmsub213sd',
    'vfmsub231ps', 'vfmsub231pd', 'vfmsub231ss', 'vfmsub231sd',
    'vfnmadd132ps', 'vfnmadd132pd', 'vfnmadd132ss', 'vfnmadd132sd',
    'vfnmadd213ps', 'vfnmadd213pd', 'vfnmadd213ss', 'vfnmadd213sd',
    'vfnmadd231ps', 'vfnmadd231pd', 'vfnmadd231ss', 'vfnmadd231sd',
    'vfnmsub132ps', 'vfnmsub132pd', 'vfnmsub132ss', 'vfnmsub132sd',
    'vfnmsub213ps', 'vfnmsub213pd', 'vfnmsub213ss', 'vfnmsub213sd',
    'vfnmsub231ps', 'vfnmsub231pd', 'vfnmsub231ss', 'vfnmsub231sd',
}
_ALL_ARITH_BITWISE = (
    _ARITH_BASIC | _ARITH_BITLOG | _ARITH_SHIFT | _ARITH_X87 |
    _ARITH_SSE_SCALAR | _ARITH_SSE_PACKED | _ARITH_SSE_INT |
    _ARITH_AVX | _ARITH_FMA
)

def is_arith_bitwise_inst(mnem):
    if mnem in _ALL_ARITH_BITWISE:
        return True
    return False

def is_mem_inst(ea, mnem):
    """
    True if instruction has an explicit memory operand or is a string memory op.
    lea, call, push/pop register do not count. push/pop [mem] counts via operand check.
    """
    if is_call_inst(mnem):
        return False

    if mnem == "lea":
        return False

    if mnem in STRING_MEMORY_MNEMS:
        return True

    try:
        for i in range(8):
            t = idc.get_operand_type(ea, i)
            if t == idaapi.o_void:
                break
            if t in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase):
                return True
            op = (idc.print_operand(ea, i) or '').lower()
            if '[' in op and ']' in op:
                return True
    except Exception:
        pass
    return False

def is_call_inst(mnem):
    return mnem in {"call", "callq"} or mnem.startswith("call")

# ======================= UNIFIED INSTRUCTION FEATURE EXTRACTOR =======================
# _REF_OPERAND_TYPES is populated by import_ida_modules() because it depends
# on idaapi constants which are unavailable at module import time outside IDA.

def extract_instruction_features(ea, string_addrs):
    """
    Return dict with instruction-level feature increments for a single instruction.
    Uses DataRefsFrom as primary source for string/const-data refs, operand value as fallback.
    """
    res = {name: 0.0 for name in INSTRUCTION_ATTRS}
    res["bb_instruction_count"] = 1.0

    mnem = get_base_mnemonic(ea)
    if not mnem:
        return res

    if is_cmp_inst(mnem):
        res["cmp_inst_count"] += 1.0
    elif is_arith_bitwise_inst(mnem):
        res["arith_bitwise_count"] += 1.0

    if is_mem_inst(ea, mnem):
        res["mem_inst_count"] += 1.0

    if is_call_inst(mnem):
        res["call_count"] += 1.0

    # Primary: DataRefsFrom for string/const-data references (dedup per target)
    seen_string_refs = set()
    seen_const_refs = set()
    try:
        for ref in idautils.DataRefsFrom(ea):
            if ref in (None, idc.BADADDR):
                continue
            if is_string_addr(ref, string_addrs):
                if ref not in seen_string_refs:
                    res["string_literal_ref_count"] += 1.0
                    seen_string_refs.add(ref)
            elif is_const_data_addr(ref):
                if ref not in seen_const_refs:
                    res["const_data_ref_count"] += 1.0
                    seen_const_refs.add(ref)
    except Exception:
        pass

    # Fallback: operand values for immediates, string/const refs not caught by DataRefsFrom
    try:
        for i in range(6):
            t = idc.get_operand_type(ea, i)
            if t == idaapi.o_void:
                break
            if t not in _REF_OPERAND_TYPES:
                continue
            v = idc.get_operand_value(ea, i)

            if t == idaapi.o_imm:
                cls = classify_operand_value(v, string_addrs)
                if cls == "string_ref":
                    if v not in seen_string_refs:
                        res["string_literal_ref_count"] += 1.0
                        seen_string_refs.add(v)
                elif cls == "const_data_ref":
                    if v not in seen_const_refs:
                        res["const_data_ref_count"] += 1.0
                        seen_const_refs.add(v)
                elif cls == "numeric_immediate":
                    if FILTER_TRIVIAL_IMMEDIATES and is_trivial_immediate(v):
                        pass
                    else:
                        res["numeric_immediate_count"] += 1.0
                # code_ref / address_ref / unknown -> do nothing for numeric counting
            else:
                if v is not None and v != 0 and v != idc.BADADDR:
                    if is_string_addr(v, string_addrs):
                        if v not in seen_string_refs:
                            res["string_literal_ref_count"] += 1.0
                            seen_string_refs.add(v)
                    elif is_const_data_addr(v):
                        if v not in seen_const_refs:
                            res["const_data_ref_count"] += 1.0
                            seen_const_refs.add(v)
    except Exception:
        pass

    return res

# ======================= BASIC BLOCKS =======================
class BBlock(object):
    def __init__(self, func_ea, start_ea):
        self.func_ea = func_ea
        self.addr = start_ea
        self.raw_attrs = {name: 0.0 for name in ATTR_NAMES}
        self.norm_attrs = {name: 0.0 for name in ATTR_NAMES}
        self.debug = {}

    def inc_raw_attr(self, name, delta=1.0):
        self.raw_attrs[name] = float(self.raw_attrs.get(name, 0.0)) + float(delta)

    def set_raw_attr(self, name, value):
        self.raw_attrs[name] = float(value)

    def get_raw_attr(self, name):
        return float(self.raw_attrs.get(name, 0.0))

    def set_norm_attr(self, name, value):
        self.norm_attrs[name] = float(value)

    def get_norm_attr(self, name):
        return float(self.norm_attrs.get(name, 0.0))

    def to_attr_list(self):
        return [self.get_raw_attr(name) for name in ATTR_NAMES]

    def to_attr_list_norm(self):
        return [self.get_norm_attr(name) for name in ATTR_NAMES]

class BBWrapper(object):
    def __init__(self, ea, bb):
        self.ea_ = ea
        self.bb_ = bb
    def get_bb(self):
        return self.bb_
    def __lt__(self, o):
        return self.ea_ < o.ea_
    def __eq__(self, o):
        return self.ea_ == o.ea_

class BBCache(object):
    def __init__(self):
        self.arr = []
        for f in idautils.Functions():
            fn = idaapi.get_func(f)
            if not fn:
                continue
            for bb in idaapi.FlowChart(fn, flags=idaapi.FC_PREDS):
                self.arr.append(BBWrapper(bb.start_ea, bb))
        self.arr.sort(key=lambda x: x.ea_)

    def get_cache_size(self):
        return len(self.arr)

    def find_block(self, ea):
        lo, hi = 0, len(self.arr)
        while lo < hi:
            mid = (lo + hi) // 2
            if ea < self.arr[mid].ea_:
                hi = mid
            else:
                lo = mid + 1
        if lo == 0:
            return None
        cand = self.arr[lo - 1].get_bb()
        if cand and cand.start_ea <= ea < cand.end_ea:
            return cand
        return None

# ======================= NORMALIZATION =======================
def _mean_std(xs):
    n = float(len(xs))
    if n == 0:
        return 0.0, 1.0
    mu = sum(xs) / n
    var = sum((x - mu) ** 2 for x in xs) / n
    sd = math.sqrt(var)
    return mu, sd

def normalize_blocks(blocks):
    if not blocks:
        return
    bblist = list(blocks.values())
    for name in ATTR_NAMES:
        raw_values = [b.get_raw_attr(name) for b in bblist]

        if name in LOG1P_FEATURES:
            values = [math.log1p(max(0.0, x)) for x in raw_values]
        else:
            values = raw_values

        if name in RAW_BINARY_FEATURES:
            for b, v in zip(bblist, values):
                b.set_norm_attr(name, finite_or_zero(float(v)))
            continue

        mu, sd = _mean_std(values)
        if sd < 1e-12:
            for b in bblist:
                b.set_norm_attr(name, 0.0)
        else:
            for b, v in zip(bblist, values):
                b.set_norm_attr(name, finite_or_zero((v - mu) / sd))

# ======================= APAGERANK =======================
def run_apagerank(CFG, blocks, attr_names,
                  damping=APAGERANK_DAMPING,
                  gamma=APAGERANK_GAMMA,
                  tau=APAGERANK_TAU,
                  epsilon=APAGERANK_EPSILON,
                  iter_max=APAGERANK_ITER_MAX):
    if not blocks:
        return

    nodes = list(blocks.keys())

    preds = defaultdict(set)
    indeg = defaultdict(int)
    outdeg = defaultdict(int)

    for u, outs in CFG.items():
        if u not in blocks:
            continue
        outs_filtered = [v for v in outs if v in blocks]
        outdeg[u] = len(outs_filtered)
        for v in outs_filtered:
            preds[v].add(u)
            indeg[v] += 1

    for n in nodes:
        _ = indeg[n]
        _ = outdeg[n]
        _ = preds[n]

    for attr in attr_names:
        w_prev = {}
        for n in nodes:
            w_prev[n] = float(blocks[n].get_norm_attr(attr))

        if not w_prev:
            continue

        if VERBOSE:
            print(f"[+] APageRank: attr '{attr}' start, "
                  f"iters <= {iter_max}, eps={epsilon}")

        for it in range(iter_max):
            w_next = {}
            max_delta = 0.0

            for x in nodes:
                old_val = w_prev[x]
                acc = 0.0
                for y in preds[x]:
                    wy = w_prev[y]
                    Oy = outdeg.get(y, 0)
                    if Oy <= 0:
                        continue
                    denom = float(Oy) * pow(float(indeg.get(x, 0)) + tau, gamma)
                    if denom != 0.0:
                        acc += wy / denom
                new_val = (1.0 - damping) * old_val + damping * acc
                w_next[x] = new_val

            for n in nodes:
                delta = abs(w_next[n] - w_prev[n])
                if delta > max_delta:
                    max_delta = delta

            w_prev = w_next

            if VERBOSE:
                print(f"    iter {it+1}: max_delta={max_delta:.6f}")

            if max_delta < epsilon:
                if VERBOSE:
                    print(f"[+] APageRank: attr '{attr}' converged at iter {it+1}")
                break
        else:
            if VERBOSE:
                print(f"[+] APageRank: attr '{attr}' reached iter_max={iter_max}")

        for n, val in w_prev.items():
            blocks[n].set_norm_attr(attr, val)

# ======================= SANCOV PC-TABLE =======================
def collect_pcs_aligned_with_counters():
    pcs_start, pcs_end = get_seg_bounds('__sancov_pcs')
    cnt_start, cnt_end = get_seg_bounds('__sancov_cntrs')
    if pcs_start is None or cnt_start is None:
        raise RuntimeError('Could not find __sancov_pcs or __sancov_cntrs segments')

    target_count = int(cnt_end - cnt_start)
    if target_count <= 0:
        raise RuntimeError('__sancov_cntrs length is 0')

    pcs = []
    ea = pcs_start
    while ea + 8 <= pcs_end and len(pcs) < target_count:
        q = read_qword_safe(ea)
        if is_plausible_code_addr(q):
            pcs.append(q)
            ea += 16
        else:
            ea += 8
    if len(pcs) < target_count:
        log.warning(f"Only parsed {len(pcs)} PCs from __sancov_pcs, fewer than counters={target_count}; truncating to the smaller count")
    return pcs[:target_count]

# ======================= TARGET-ONLY FUNCTION SET =======================
def resolve_seed_entries(pcs):
    seeds = []
    for name in SEED_ENTRY_NAMES:
        ea = idc.get_name_ea_simple(name)
        if ea != idc.BADADDR:
            seeds.append(ea)
    if seeds:
        return list(set(seeds))
    if pcs:
        bb_fn = idaapi.get_func(pcs[0])
        if bb_fn:
            return [bb_fn.start_ea]
    raise RuntimeError("No usable entry function found (neither LLVMFuzzerTestOneInput nor a function inferred from the first PC)")

def function_filter(f):
    try:
        flags = idc.get_func_attr(f, idc.FUNCATTR_FLAGS)
        if flags == idc.BADADDR:
            return False
        if (flags & idc.FUNC_LIB) or (flags & idc.FUNC_THUNK):
            return False
        segname = idc.get_segm_name(f) or ''
        if segname.lower() not in ('.text', 'text', 'code', '__text'):
            return False
        fn = idaapi.get_func(f)
        if fn and (fn.end_ea - fn.start_ea) < 4:
            return False
        return True
    except Exception:
        return False

_TAIL_CALL_JUMP_MNEMS = {"jmp", "jmpq"}


def build_function_call_graph():
    """Build a function-level call graph for reachability from seeds.

    Records two kinds of edges:
      * Direct calls (``call`` / ``callq`` etc.).
      * Tail-call jumps: an unconditional ``jmp`` whose target is the
        ENTRY of a different function. Clang routinely emits these
        for ``LLVMFuzzerTestOneInput`` wrappers and many small thunks;
        if we don't follow them, reachability collapses to just the
        wrapper itself.
    """
    call_graph = defaultdict(set)
    funcs = [f for f in idautils.Functions() if function_filter(f)]
    for f in funcs:
        fn = idaapi.get_func(f)
        if not fn:
            continue
        ea = fn.start_ea
        end = fn.end_ea
        cur = ea
        while cur < end and cur != idc.BADADDR:
            m = get_base_mnemonic(cur)
            is_call = is_call_inst(m)
            is_uncond_jmp = m in _TAIL_CALL_JUMP_MNEMS
            if is_call or is_uncond_jmp:
                targets = set()
                try:
                    for r in idautils.CodeRefsFrom(cur, False):
                        if r not in (None, idc.BADADDR):
                            targets.add(r)
                except Exception:
                    pass
                if not targets:
                    tgt = idc.get_operand_value(cur, 0)
                    if tgt not in (None, idc.BADADDR):
                        targets.add(tgt)
                for tgt in targets:
                    tgt_fn = idaapi.get_func(tgt)
                    if not tgt_fn:
                        continue
                    if is_uncond_jmp:
                        # Only treat ``jmp`` as a tail call when it lands
                        # exactly on a DIFFERENT function's entry. Intra-
                        # function ``jmp`` to a basic block is a regular
                        # CFG edge and must not pollute the call graph.
                        if tgt_fn.start_ea != tgt:
                            continue
                        if tgt_fn.start_ea == fn.start_ea:
                            continue
                    if function_filter(tgt_fn.start_ea):
                        call_graph[ea].add(tgt_fn.start_ea)
            cur = idc.next_head(cur)
            if cur == idc.BADADDR:
                break
    return call_graph

def reachable_from_seeds(call_graph, seeds):
    vis = set()
    q = deque()
    for s in seeds:
        if function_filter(s):
            vis.add(s)
            q.append(s)
    while q:
        u = q.popleft()
        for v in call_graph.get(u, ()):
            if v not in vis:
                vis.add(v)
                q.append(v)
    return vis

# ======================= TARGET-ONLY CFG & INSTRUCTION FEATURES =======================
def build_target_cfg_and_features(target_funcs):
    CFG = defaultdict(set)
    blocks = {}
    func_of_bb = {}

    string_addrs = get_all_ida_strings()

    for f in target_funcs:
        fn = idaapi.get_func(f)
        if not fn:
            continue
        fc = idaapi.FlowChart(fn, flags=idaapi.FC_PREDS)
        for bb in fc:
            b = BBlock(fn.start_ea, bb.start_ea)
            ea = bb.start_ea
            while ea < bb.end_ea and ea != idc.BADADDR:
                features = extract_instruction_features(ea, string_addrs)
                for name, delta in features.items():
                    b.inc_raw_attr(name, delta)
                ea = idc.next_head(ea)
                if ea == idc.BADADDR:
                    break
            blocks[bb.start_ea] = b
            func_of_bb[bb.start_ea] = fn.start_ea
            _ = CFG[bb.start_ea]

        for bb in fc:
            src = bb.start_ea
            for succ in bb.succs():
                dst = succ.start_ea
                if src in blocks and dst in blocks:
                    CFG[src].add(dst)

    return CFG, blocks, func_of_bb

# ======================= ITERATIVE SCC (Kosaraju) =======================
def compute_sccs_iterative(adj, nodes):
    """
    Iterative Kosaraju SCC. Returns list of sets. No recursion.
    """
    nodes = list(nodes)
    node_set = set(nodes)

    radj = {n: set() for n in nodes}
    for u in nodes:
        for v in adj.get(u, ()):
            if v in node_set:
                radj.setdefault(v, set()).add(u)

    visited = set()
    order = []

    for start in nodes:
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            n, expanded = stack.pop()
            if expanded:
                order.append(n)
                continue
            if n in visited:
                continue
            visited.add(n)
            stack.append((n, True))
            for v in adj.get(n, ()):
                if v in node_set and v not in visited:
                    stack.append((v, False))

    visited.clear()
    sccs = []

    for start in reversed(order):
        if start in visited:
            continue
        comp = set()
        stack = [start]
        visited.add(start)
        while stack:
            n = stack.pop()
            comp.add(n)
            for v in radj.get(n, ()):
                if v not in visited:
                    visited.add(v)
                    stack.append(v)
        sccs.append(comp)

    return sccs

# ======================= STRUCTURAL FEATURES =======================

# ---- CFG degree ----
def compute_cfg_degree_features(CFG, blocks):
    preds = defaultdict(int)
    for u, outs in CFG.items():
        for v in outs:
            if v in blocks:
                preds[v] += 1

    for bb_ea, b in blocks.items():
        b.set_raw_attr("cfg_out_degree", float(len(CFG.get(bb_ea, set()))))
        b.set_raw_attr("cfg_in_degree", float(preds.get(bb_ea, 0)))

# ---- Static descendant / ancestor (SCC condensation) ----
def _compute_reachable_sizes_on_dag(dag, scc_sizes, scc_order):
    reachable = {}
    for scc_id in reversed(scc_order):
        visited_sccs = set()
        dq = deque()
        for succ in dag.get(scc_id, ()):
            if succ not in visited_sccs:
                visited_sccs.add(succ)
                dq.append(succ)
        while dq:
            x = dq.popleft()
            for y in dag.get(x, ()):
                if y not in visited_sccs:
                    visited_sccs.add(y)
                    dq.append(y)
        total = sum(scc_sizes[s] for s in visited_sccs)
        total += scc_sizes[scc_id] - 1
        reachable[scc_id] = total
    return reachable

def compute_static_reachability_features(CFG, blocks):
    nodes = set(blocks.keys())
    if not nodes:
        return

    sccs = compute_sccs_iterative(CFG, nodes)

    node_to_scc = {}
    scc_sizes = {}
    for idx, scc in enumerate(sccs):
        scc_sizes[idx] = len(scc)
        for n in scc:
            node_to_scc[n] = idx

    scc_dag_fwd = defaultdict(set)
    for u in nodes:
        u_scc = node_to_scc[u]
        for v in CFG.get(u, ()):
            if v in nodes:
                v_scc = node_to_scc[v]
                if u_scc != v_scc:
                    scc_dag_fwd[u_scc].add(v_scc)

    scc_dag_rev = defaultdict(set)
    for u_scc, succs in scc_dag_fwd.items():
        for v_scc in succs:
            scc_dag_rev[v_scc].add(u_scc)

    scc_order = list(range(len(sccs)))

    descendant_reachable = _compute_reachable_sizes_on_dag(scc_dag_fwd, scc_sizes, scc_order)
    ancestor_reachable = _compute_reachable_sizes_on_dag(scc_dag_rev, scc_sizes, scc_order)

    for bb_ea, b in blocks.items():
        scc_id = node_to_scc.get(bb_ea)
        if scc_id is not None:
            b.set_raw_attr("static_descendant_count", float(descendant_reachable.get(scc_id, 0)))
            b.set_raw_attr("static_ancestor_count", float(ancestor_reachable.get(scc_id, 0)))

# ---- Entry depth ----
def compute_depth_attribute(CFG, blocks, func_of_bb, call_graph, seeds):
    func_depth = defaultdict(lambda: 0.0)
    INF = 1 << 30
    tmp = defaultdict(lambda: INF)
    dq = deque()
    for s in seeds:
        if function_filter(s):
            tmp[s] = 0
            dq.append(s)
    while dq:
        u = dq.popleft()
        for v in call_graph.get(u, ()):
            if tmp[v] > tmp[u] + 1:
                tmp[v] = tmp[u] + 1
                dq.append(v)
    for f, d in tmp.items():
        if d != INF:
            func_depth[f] = float(d)

    preds = defaultdict(set)
    for u, outs in CFG.items():
        for v in outs:
            preds[v].add(u)

    func_to_bbs = defaultdict(list)
    for bb_ea, f_ea in func_of_bb.items():
        func_to_bbs[f_ea].append(bb_ea)

    func_entry_bb = {}
    for f_ea, bb_list in func_to_bbs.items():
        sset = set(bb_list)
        entry_candidates = [b for b in bb_list if not (preds[b] & sset)]
        func_entry_bb[f_ea] = entry_candidates[0] if entry_candidates else min(bb_list)

    intra_depth = {}
    for f_ea, entry_bb in func_entry_bb.items():
        sset = set(func_to_bbs.get(f_ea, []))
        dist = defaultdict(lambda: INF)
        dq2 = deque([entry_bb])
        dist[entry_bb] = 0
        while dq2:
            x = dq2.popleft()
            for y in CFG.get(x, ()):
                if y in sset and dist[y] == INF:
                    dist[y] = dist[x] + 1
                    dq2.append(y)
        for b in sset:
            intra_depth[b] = 0 if dist[b] == INF else dist[b]

    for bb_ea, b in blocks.items():
        f_ea = func_of_bb.get(bb_ea, None)
        d_func = func_depth.get(f_ea, 0.0)
        d_intra = float(intra_depth.get(bb_ea, 0))
        b.set_raw_attr("entry_depth", d_func + d_intra)

# ---- Loop features (natural loop with same-header merge + SCC fallback) ----
def _add_loop_role(roles_debug, node, role):
    if role not in roles_debug[node]:
        roles_debug[node].append(role)

def compute_loop_features(CFG, blocks, func_of_bb):
    func_to_bbs = defaultdict(set)
    for bb_ea, f_ea in func_of_bb.items():
        func_to_bbs[f_ea].add(bb_ea)

    loop_nesting = defaultdict(int)
    loop_boundary = defaultdict(float)
    loop_roles_debug = defaultdict(list)

    for f_ea, func_bbs in func_to_bbs.items():
        if not func_bbs:
            continue

        func_succs = defaultdict(set)
        func_preds = defaultdict(set)
        for u in func_bbs:
            for v in CFG.get(u, ()):
                if v in func_bbs:
                    func_succs[u].add(v)
                    func_preds[v].add(u)

        entry_candidates = [b for b in func_bbs if not func_preds[b]]
        entry_bb = entry_candidates[0] if entry_candidates else min(func_bbs)

        # Compute dominators (iterative dataflow)
        dom = {entry_bb: {entry_bb}}
        for n in func_bbs:
            if n != entry_bb:
                dom[n] = set(func_bbs)

        changed = True
        while changed:
            changed = False
            for n in func_bbs:
                if n == entry_bb:
                    continue
                pred_set = func_preds.get(n, set())
                if not pred_set:
                    new_dom = {n}
                else:
                    new_dom = set.intersection(*(dom.get(p, set()) for p in pred_set))
                    new_dom = new_dom | {n}
                if new_dom != dom[n]:
                    dom[n] = new_dom
                    changed = True

        # Identify back edges (u -> v where v dominates u)
        back_edges = []
        for u in func_bbs:
            for v in func_succs.get(u, ()):
                if v in dom.get(u, set()):
                    back_edges.append((u, v))

        # For each back edge, recover natural loop
        raw_loops = []
        for latch, header in back_edges:
            loop_nodes = {header}
            if latch != header:
                loop_nodes.add(latch)
                work = [latch]
                while work:
                    node = work.pop()
                    for pred in func_preds.get(node, ()):
                        if pred not in loop_nodes and pred in func_bbs:
                            loop_nodes.add(pred)
                            work.append(pred)
            raw_loops.append((header, latch, frozenset(loop_nodes)))

        # Merge same-header natural loops
        loops_by_header = {}
        latches_by_header = defaultdict(set)
        for header, latch, loop_nodes in raw_loops:
            if header not in loops_by_header:
                loops_by_header[header] = set()
            loops_by_header[header].update(loop_nodes)
            latches_by_header[header].add(latch)

        for header, loop_nodes in loops_by_header.items():
            for n in loop_nodes:
                loop_nesting[n] += 1

            loop_boundary[header] = 1.0
            _add_loop_role(loop_roles_debug, header, "header")
            _add_loop_role(loop_roles_debug, header, "backedge_target")

            for latch in latches_by_header[header]:
                loop_boundary[latch] = 1.0
                _add_loop_role(loop_roles_debug, latch, "latch")
                _add_loop_role(loop_roles_debug, latch, "backedge_source")

            for n in loop_nodes:
                for s in func_succs.get(n, ()):
                    if s not in loop_nodes:
                        loop_boundary[n] = 1.0
                        loop_boundary[s] = 1.0
                        _add_loop_role(loop_roles_debug, n, "exit_source")
                        _add_loop_role(loop_roles_debug, s, "exit_target")

        # SCC fallback
        func_sccs = compute_sccs_iterative(func_succs, func_bbs)
        for scc in func_sccs:
            is_loop_scc = False
            if len(scc) > 1:
                is_loop_scc = True
            elif len(scc) == 1:
                n = next(iter(scc))
                if n in func_succs.get(n, set()):
                    is_loop_scc = True

            if not is_loop_scc:
                continue

            for n in scc:
                loop_nesting[n] = max(loop_nesting[n], 1)

                for p in func_preds.get(n, ()):
                    if p not in scc:
                        loop_boundary[n] = 1.0
                        _add_loop_role(loop_roles_debug, n, "scc_entry")

                for s in func_succs.get(n, ()):
                    if s not in scc:
                        loop_boundary[n] = 1.0
                        loop_boundary[s] = 1.0
                        _add_loop_role(loop_roles_debug, n, "scc_exit_source")
                        _add_loop_role(loop_roles_debug, s, "scc_exit_target")

    for bb_ea, b in blocks.items():
        b.set_raw_attr("loop_nesting_depth", float(loop_nesting.get(bb_ea, 0)))
        b.set_raw_attr("loop_boundary_flag", float(loop_boundary.get(bb_ea, 0.0)))
        if bb_ea in loop_roles_debug:
            b.debug["loop_roles"] = loop_roles_debug[bb_ea]

# ---- Centrality (betweenness, Brandes with sampled scaling) ----
def compute_centrality_feature(CFG, blocks):
    nodes = list(blocks.keys())
    N = len(nodes)
    if N == 0:
        return

    sample_nodes = nodes
    if N > CENTRALITY_EXACT_MAX:
        import random
        random.seed(CENTRALITY_SAMPLE_SEED)
        sample_nodes = random.sample(nodes, min(CENTRALITY_SAMPLE_MAX, N))

    btw_acc = defaultdict(float)
    node_set = set(nodes)

    for s in sample_nodes:
        S = []
        P = defaultdict(list)
        sigma = defaultdict(float)
        sigma[s] = 1.0
        dist = defaultdict(lambda: -1)
        dist[s] = 0
        Q = deque([s])
        while Q:
            v = Q.popleft()
            S.append(v)
            for w in CFG.get(v, ()):
                if w not in node_set:
                    continue
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    Q.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    P[w].append(v)
        delta = defaultdict(float)
        while S:
            w = S.pop()
            for v in P[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                btw_acc[w] += delta[w]

    sample_size = len(sample_nodes)
    if sample_size > 0 and sample_size < N:
        scale = float(N) / float(sample_size)
    else:
        scale = 1.0

    norm = (sample_size - 1) * (N - 1) if N > 1 else 1.0
    if norm <= 0:
        norm = 1.0
    for bb_ea in nodes:
        raw = btw_acc.get(bb_ea, 0.0) * scale
        blocks[bb_ea].set_raw_attr("centrality", float(raw / norm))

# ======================= FEATURE MODE =======================
def apply_feature_mode(blocks, feature="both"):
    if feature == "semantic":
        for b in blocks.values():
            for name in STRUCTURAL_ATTRS:
                b.set_raw_attr(name, 0.0)
    elif feature == "graph":
        for b in blocks.values():
            for name in INSTRUCTION_ATTRS:
                b.set_raw_attr(name, 0.0)

# ======================= REACHABLE EDGES =======================
def count_reachable_edges(CFG, func_of_bb, target_funcs):
    func_to_bbs = defaultdict(list)
    for bb, f in func_of_bb.items():
        if f in target_funcs:
            func_to_bbs[f].append(bb)

    total_edges = 0
    for f_ea, bbs in func_to_bbs.items():
        if not bbs:
            continue
        sset = set(bbs)
        preds = defaultdict(set)
        for u in sset:
            for v in CFG.get(u, ()):
                if v in sset:
                    preds[v].add(u)
        entry_candidates = [b for b in bbs if not (preds[b] & sset)]
        entry_bb = entry_candidates[0] if entry_candidates else min(bbs)

        vis = {entry_bb}
        dq = deque([entry_bb])
        while dq:
            u = dq.popleft()
            for v in CFG.get(u, ()):
                if v in sset and v not in vis:
                    vis.add(v)
                    dq.append(v)
        for u in vis:
            total_edges += sum(1 for v in CFG.get(u, ()) if v in vis)

    return int(total_edges)

# ======================= WEIGHT / FEATURES MAP =======================
def l2_norm(vec):
    return math.sqrt(sum(float(x) * float(x) for x in vec))

def _is_one_hot(u, tol=1e-12):
    idx = -1
    cnt = 0
    for i, ui in enumerate(u):
        if abs(float(ui)) > tol:
            cnt += 1
            idx = i
            if cnt > 1:
                return False, -1
    return (cnt == 1), idx

def directional_weight(z_vals, u=None):
    if not z_vals:
        return 0.0
    d = len(z_vals)

    if u is not None and len(u) == d:
        is_one_hot, idx = _is_one_hot(u)
        if is_one_hot:
            return float(z_vals[idx])

    if u is None or len(u) != d:
        dot_over_unorm = sum(float(z) for z in z_vals) / math.sqrt(d)
    else:
        u_norm = math.sqrt(sum(float(ui) * float(ui) for ui in u))
        if u_norm == 0.0:
            dot_over_unorm = sum(float(z) for z in z_vals) / math.sqrt(d)
        else:
            dot_over_unorm = sum(float(zi) * float(ui) for zi, ui in zip(z_vals, u)) / u_norm

    mag = math.sqrt(sum(float(z) * float(z) for z in z_vals))
    return dot_over_unorm * mag

# ======================= SANITY CHECKS =======================
def validate_features(pcs, CFG, blocks):
    errors = []
    if len(ATTR_NAMES) != 16:
        errors.append(f"ATTR_NAMES length is {len(ATTR_NAMES)}, expected 16")

    # Build predecessor map for in-degree validation
    pred_count = defaultdict(int)
    for u, outs in CFG.items():
        for v in outs:
            if v in blocks:
                pred_count[v] += 1

    for bb_ea, b in blocks.items():
        if set(b.raw_attrs.keys()) != set(ATTR_NAMES):
            errors.append(f"BB {hex(bb_ea)}: raw_attrs keys mismatch")
        if set(b.norm_attrs.keys()) != set(ATTR_NAMES):
            errors.append(f"BB {hex(bb_ea)}: norm_attrs keys mismatch")
        for name in ATTR_NAMES:
            rv = b.get_raw_attr(name)
            nv = b.get_norm_attr(name)
            if math.isnan(rv) or math.isinf(rv):
                errors.append(f"BB {hex(bb_ea)}: raw {name} is {rv}")
            if math.isnan(nv) or math.isinf(nv):
                errors.append(f"BB {hex(bb_ea)}: norm {name} is {nv}")
        lbf = b.get_raw_attr("loop_boundary_flag")
        if lbf not in (0.0, 1.0):
            errors.append(f"BB {hex(bb_ea)}: loop_boundary_flag is {lbf}")
        if b.get_raw_attr("loop_nesting_depth") < 0:
            errors.append(f"BB {hex(bb_ea)}: loop_nesting_depth is negative")
        if b.get_raw_attr("static_descendant_count") < 0:
            errors.append(f"BB {hex(bb_ea)}: static_descendant_count is negative")
        if b.get_raw_attr("static_ancestor_count") < 0:
            errors.append(f"BB {hex(bb_ea)}: static_ancestor_count is negative")
        expected_out = float(len(CFG.get(bb_ea, set())))
        if b.get_raw_attr("cfg_out_degree") != expected_out:
            errors.append(f"BB {hex(bb_ea)}: cfg_out_degree mismatch")
        expected_in = float(pred_count.get(bb_ea, 0))
        if b.get_raw_attr("cfg_in_degree") != expected_in:
            errors.append(f"BB {hex(bb_ea)}: cfg_in_degree mismatch")

    if errors:
        for e in errors[:20]:
            log.warning(f"Validation: {e}")
        if len(errors) > 20:
            log.warning(f"... and {len(errors) - 20} more validation issues")
    else:
        print("[+] Validation passed: all 16 features consistent across all blocks")

    # Summary statistics
    print(f"\n{'feature_name':<30s} {'min':>10s} {'max':>10s} {'mean':>10s} {'std':>10s} {'zero':>6s} {'nonzero':>7s}")
    print("-" * 83)
    bblist = list(blocks.values())
    for name in ATTR_NAMES:
        vals = [b.get_raw_attr(name) for b in bblist]
        if not vals:
            continue
        mn = min(vals)
        mx = max(vals)
        mu = sum(vals) / len(vals)
        var = sum((x - mu) ** 2 for x in vals) / len(vals)
        sd = math.sqrt(var)
        zc = sum(1 for v in vals if v == 0.0)
        nz = len(vals) - zc
        print(f"{name:<30s} {mn:10.3f} {mx:10.3f} {mu:10.3f} {sd:10.3f} {zc:6d} {nz:7d}")

def validate_exported_maps(attr_arrays, pcs):
    if set(attr_arrays.keys()) != set(ATTR_NAMES):
        raise RuntimeError("exported feature map keys do not match ATTR_NAMES")

    for name in ATTR_NAMES:
        arr = attr_arrays.get(name)
        if arr is None:
            raise RuntimeError("missing feature array: %s" % name)

        if len(arr) != len(pcs):
            raise RuntimeError(
                "feature array length mismatch for %s: got %d, expected %d"
                % (name, len(arr), len(pcs))
            )

        for x in arr:
            if not math.isfinite(float(x)):
                raise RuntimeError("non-finite value in feature array: %s" % name)

# ======================= EXPORT =======================
def _cross_platform_basename(path):
    """Return the basename of ``path`` treating both '/' and '\\\\' as separators.

    Needed because ``ida_nalt.get_input_file_path()`` can return Windows-style
    paths when the IDB was originally created on Windows.
    """
    if not path:
        return path
    return os.path.basename(path.replace("\\", "/"))


def build_and_save_features_map(pcs, CFG, blocks, func_of_bb, reachable_edges=None,
                                 out_dir_override=None, base_override=None):
    bin_path = ida_nalt.get_input_file_path()
    base = base_override or _cross_platform_basename(bin_path)
    out_dir = out_dir_override or os.path.dirname(bin_path) or os.getcwd()

    bb_cache = BBCache()

    fmap = []
    dbg = []
    target_bb_set = set(blocks.keys())

    for idx, pc in enumerate(pcs):
        bb = bb_cache.find_block(pc)
        if not bb:
            fmap.append(EPS_NON_TARGET)
            dbg.append({
                "index": idx,
                "pc": hex(pc),
                "bb_start": None,
                "func": None,
                "attrs_raw": None,
                "attrs_norm": None,
                "debug": None,
                "weight": float(EPS_NON_TARGET),
                "note": "no_bb"
            })
            continue

        start = bb.start_ea
        if start in target_bb_set:
            b = blocks[start]
            w = directional_weight(b.to_attr_list_norm())
            fmap.append(float(w))
            dbg.append({
                "index": idx,
                "pc": hex(pc),
                "bb_start": hex(start),
                "func": hex(b.func_ea),
                "attrs_raw": dict(b.raw_attrs),
                "attrs_norm": dict(b.norm_attrs),
                "debug": dict(getattr(b, "debug", {})),
                "weight": float(w),
            })
        else:
            fmap.append(EPS_NON_TARGET)
            dbg.append({
                "index": idx,
                "pc": hex(pc),
                "bb_start": hex(start),
                "func": None,
                "attrs_raw": None,
                "attrs_norm": None,
                "debug": None,
                "weight": float(EPS_NON_TARGET),
                "note": "non_target"
            })

    out_path = os.path.join(out_dir, f"{base}_features_map_default.json")
    with open(out_path, "w") as f:
        json.dump(fmap, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved features_map_default -> {out_path}")

    dbg_path = os.path.join(out_dir, f"{base}_features_map.debug.json")
    dbg_payload = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "attr_names": ATTR_NAMES,
        "normalization": {
            "default": "zscore(raw)",
            "log1p_features": sorted(LOG1P_FEATURES),
            "raw_binary_features": sorted(RAW_BINARY_FEATURES),
        },
        "apagerank_enabled": USE_APAGERANK,
        "reachable_edges": reachable_edges,
        "pcs": [hex(p) for p in pcs],
        "map": dbg,
    }
    with open(dbg_path, "w") as f:
        json.dump(dbg_payload, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved debug map   -> {dbg_path}")

    return out_path, dbg_path

def build_and_save_features_map_for_u(pcs, blocks, func_of_bb, u, out_filename,
                                       out_dir_override=None):
    bin_path = ida_nalt.get_input_file_path()
    out_dir = out_dir_override or os.path.dirname(bin_path) or os.getcwd()

    bb_cache = BBCache()
    target_bb_set = set(blocks.keys())

    fmap = []
    for idx, pc in enumerate(pcs):
        bb = bb_cache.find_block(pc)
        if not bb:
            fmap.append(float(EPS_NON_TARGET))
            continue

        start = bb.start_ea
        if start in target_bb_set:
            b = blocks[start]
            zn = b.to_attr_list_norm()
            w = directional_weight(zn, u=u)
            fmap.append(float(w))
        else:
            fmap.append(float(EPS_NON_TARGET))

    out_path = os.path.join(out_dir, out_filename)
    with open(out_path, "w") as f:
        json.dump(fmap, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved features_map (u provided) -> {out_path}")
    return fmap, out_path

def save_schema_json(out_dir, base, execution=None, out_dir_override=None):
    if out_dir_override:
        out_dir = out_dir_override
    schema = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(ATTR_NAMES),
        "attr_names": ATTR_NAMES,
        "feature_groups": {
            "instruction": INSTRUCTION_ATTRS,
            "structural": STRUCTURAL_ATTRS,
        },
        "normalization": {
            "default": "zscore(raw)",
            "log1p_features": sorted(LOG1P_FEATURES),
            "raw_binary_features": sorted(RAW_BINARY_FEATURES),
        },
        "target_scope": "functions reachable from LLVMFuzzerTestOneInput",
        "architecture_support": "x86/x86_64 first-class",
        "zero_policy": "target BB zeros are preserved; EPS_NON_TARGET is used only for no_bb and non_target",
        "string_detection": "IDA Strings table, explicit IDA string type, and printable __cstring only",
        "const_data_detection": "case-insensitive const-data segment matching; string refs take precedence",
        "data_reference_source": "DataRefsFrom first, operand value fallback",
        "numeric_immediate_policy": "filtered trivial immediates with signed-form handling; in-segment non-const addresses are not numeric immediates",
        "memory_instruction_policy": "explicit memory operands and x86 string memory ops count; push/pop register, call, and lea do not count",
        "cmp_instruction_policy": "cmp/test/comis/ucomis/pcmp/vpcmp/fcom/ftst/cmpxchg/cmps/scas count",
        "loop_policy": "natural loops with same-header merge; SCC fallback marks SCC entry node, not outside predecessor",
        "centrality_policy": "current Brandes-style heuristic normalization; sampled mode scaled by N/sample_size",
        "scc_implementation": "iterative Kosaraju SCC; no recursive Tarjan",
        "notes": [
            "cmp_inst_count is separate from arith_bitwise_count",
            "mem_inst_count counts explicit memory-access instructions only",
            "calls are counted in call_count only",
            "APageRank disabled by default",
            "If --input-file points to a .i64 database, output basename may include the .i64 suffix",
        ],
    }
    if execution is not None:
        schema["execution"] = execution
    schema_path = os.path.join(out_dir, f"{base}_features_schema.json")
    with open(schema_path, "w") as f:
        json.dump(schema, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved schema JSON -> {schema_path}")
    return schema_path

# ============================== CLI / BOOTSTRAP ==============================
def parse_cli_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Extract canonical BOFuzz 16-dim static BB features using IDA/IDALIB. "
            "Supports both --idapro (PyPI idapro / IDALIB) and traditional IDA -S."
        )
    )
    parser.add_argument(
        "--idapro",
        action="store_true",
        help="Run via PyPI idapro / IDALIB instead of inside IDA.",
    )
    parser.add_argument(
        "-i", "--input-file",
        default=None,
        help="Path to target binary (required when --idapro is used).",
    )
    parser.add_argument(
        "--ida-dir",
        default=None,
        help="IDA installation directory; sets IDADIR before importing idapro.",
    )
    parser.add_argument(
        "--save-idb",
        action="store_true",
        help="If set, save the IDB on close (Mode B only).",
    )
    parser.add_argument(
        "--no-auto-wait",
        action="store_true",
        help="Skip ida_auto.auto_wait() after database open / module import.",
    )
    parser.add_argument(
        "--feature-mode",
        choices=["both", "semantic", "graph"],
        default="both",
        help="Which feature groups to keep before normalization.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write feature outputs into. Defaults to dirname(input file).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser.parse_args(argv)


def _detect_inside_ida():
    """Return True if we appear to be already running inside IDA (Mode A)."""
    return "idaapi" in sys.modules or "idc" in sys.modules


def bootstrap_ida_environment(args):
    """Bring up IDA modules according to the selected execution mode.

    Mode B (--idapro): set IDADIR, import idapro, open the database, then
                       import IDA modules and (optionally) run auto_wait.
    Mode A (default):  expect to be running inside IDA already; import IDA
                       modules and (optionally) run auto_wait.
    """
    global _IDAPRO_LIB, _IDAPRO_DB_OPENED, _IDAPRO_CLOSE_SAVE
    global _RUNNING_UNDER_IDAPRO, _RUNNING_INSIDE_IDA

    if args.ida_dir:
        os.environ["IDADIR"] = args.ida_dir

    if args.idapro:
        if not args.input_file:
            raise RuntimeError("--input-file is required when --idapro is used")

        try:
            import idapro as _idapro
        except Exception as e:
            raise RuntimeError(
                "Failed to import the PyPI 'idapro' module. Make sure IDALIB is "
                "installed (e.g. via py-activate-idalib.py) and that --ida-dir "
                "points at a valid IDA installation. Original error: %r" % (e,)
            )

        _IDAPRO_LIB = _idapro
        _RUNNING_UNDER_IDAPRO = True
        _IDAPRO_CLOSE_SAVE = bool(args.save_idb)

        rc = _idapro.open_database(args.input_file, True)
        if rc != 0:
            raise RuntimeError(
                "idapro.open_database failed with rc=%r for %s"
                % (rc, args.input_file)
            )
        _IDAPRO_DB_OPENED = True

        import_ida_modules()

        if not args.no_auto_wait:
            ida_auto.auto_wait()
        return

    try:
        import_ida_modules()
        _RUNNING_INSIDE_IDA = True

        if not args.no_auto_wait:
            ida_auto.auto_wait()
        return
    except Exception as e:
        raise RuntimeError(
            "Could not import IDA modules. If running outside IDA, use: "
            "python3 static_analysis/features_extractor.py "
            "--idapro --input-file <binary> --ida-dir <ida_install_dir>. "
            "Original error: %r" % (e,)
        )


def cleanup_ida_environment():
    """Close the idapro-managed database, if any. No-op in traditional mode."""
    global _IDAPRO_LIB, _IDAPRO_DB_OPENED

    if _IDAPRO_LIB is not None and _IDAPRO_DB_OPENED:
        try:
            _IDAPRO_LIB.close_database(bool(_IDAPRO_CLOSE_SAVE))
        finally:
            _IDAPRO_DB_OPENED = False


# ========================== OUTPUT DIRECTORY HELPERS ==========================
def get_output_dir(args):
    """Resolve the absolute output directory based on CLI args and IDA state.

    Resolution order:
      1. ``--output-dir`` if provided.
      2. ``dirname(args.input_file)`` if ``--input-file`` was provided
         (preferred in Mode B, especially when the IDB stores a non-portable
         Windows path that ``ida_nalt.get_input_file_path()`` would return).
      3. ``dirname(ida_nalt.get_input_file_path())`` (traditional Mode A).
      4. The current working directory.
    """
    if args is not None and getattr(args, "output_dir", None):
        out_dir = os.path.abspath(args.output_dir)
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        return out_dir

    if args is not None and getattr(args, "input_file", None):
        in_dir = os.path.dirname(os.path.abspath(args.input_file))
        if in_dir:
            return in_dir

    bin_path = ida_nalt.get_input_file_path() if ida_nalt is not None else None
    if bin_path:
        bin_dir = os.path.dirname(bin_path.replace("\\", "/"))
        if bin_dir:
            return bin_dir
    return os.getcwd()


def _build_execution_metadata(args, bin_path, out_dir):
    """Build the execution metadata dict embedded in features_schema.json."""
    if _RUNNING_UNDER_IDAPRO:
        mode = "idapro"
    elif _RUNNING_INSIDE_IDA:
        mode = "ida_internal"
    else:
        mode = "unknown"

    meta = {
        "mode": mode,
        "cwd": os.getcwd(),
        "auto_wait": not bool(getattr(args, "no_auto_wait", False)),
        "output_dir": out_dir,
        "feature_mode": getattr(args, "feature_mode", "both"),
    }

    if mode == "idapro":
        input_file_arg = getattr(args, "input_file", None)
        meta.update({
            "input_file_arg": input_file_arg,
            "resolved_input_file": os.path.abspath(input_file_arg) if input_file_arg else None,
            "ida_dir": getattr(args, "ida_dir", None) or os.environ.get("IDADIR"),
            "save_idb": bool(getattr(args, "save_idb", False)),
            "input_file_path": bin_path,
        })
    else:
        meta["input_file_path"] = bin_path

    return meta


# ============================== EXTRACTION ==============================
def run_extraction(args):
    """Run the full extraction pipeline. Assumes IDA modules are imported."""
    if getattr(args, "verbose", False):
        log.setLevel(logging.DEBUG)

    time_start = time.time()
    bin_path = ida_nalt.get_input_file_path()
    print(f"[+] Binary: {bin_path}")
    print(f"[+] Feature schema version: {FEATURE_SCHEMA_VERSION}, dims: {len(ATTR_NAMES)}")

    pcs = collect_pcs_aligned_with_counters()
    print(f"[+] PCs collected (aligned with counters): {len(pcs)}")

    seeds = resolve_seed_entries(pcs)
    seed_names = [idc.get_func_name(ea) or hex(ea) for ea in seeds]
    print(f"[+] Seed entries: {seed_names}")

    call_g = build_function_call_graph()

    target_funcs = reachable_from_seeds(call_g, seeds)
    print(f"[+] Target-only function count: {len(target_funcs)}")

    CFG, blocks, func_of_bb = build_target_cfg_and_features(target_funcs)
    print(f"[+] Target-only CFG: {len(blocks)} basic blocks, {sum(len(v) for v in CFG.values())} edges")

    if len(blocks) == 0:
        raise RuntimeError("Target-only CFG is empty. Check entry points/reachability or build symbols.")

    print("[+] Computing CFG degree features ...")
    compute_cfg_degree_features(CFG, blocks)

    print("[+] Computing static reachability (descendant/ancestor via iterative SCC) ...")
    compute_static_reachability_features(CFG, blocks)

    print("[+] Computing depth (from entry function) ...")
    compute_depth_attribute(CFG, blocks, func_of_bb, call_g, seeds)

    print("[+] Computing loop features (natural loop with header merge + SCC fallback) ...")
    compute_loop_features(CFG, blocks, func_of_bb)

    print("[+] Computing centrality (betweenness) ...")
    compute_centrality_feature(CFG, blocks)

    feature = args.feature_mode
    apply_feature_mode(blocks, feature=feature)
    print(f"[+] Feature mode: {feature}")

    normalize_blocks(blocks)

    if USE_APAGERANK:
        if feature == "semantic":
            ap_attrs = INSTRUCTION_ATTRS
        elif feature == "graph":
            ap_attrs = STRUCTURAL_ATTRS
        else:
            ap_attrs = ATTR_NAMES

        print(f"[+] Running Attributed PageRank on {len(ap_attrs)} attributes")
        apagerank_time_start = time.time()
        run_apagerank(CFG, blocks, ap_attrs)
        apagerank_time_end = time.time()
        print(f"    APageRank Time: {apagerank_time_end - apagerank_time_start:.2f}s")

    validate_features(pcs, CFG, blocks)

    reachable_edges = count_reachable_edges(CFG, func_of_bb, target_funcs)
    if VERBOSE:
        print(f"[+] Reachable edges from entries: {reachable_edges}")

    # Choose the base name preferring the user-supplied --input-file when in
    # Mode B (avoids leaking Windows paths from older IDBs into output files).
    base = None
    if getattr(args, "input_file", None):
        base = _cross_platform_basename(args.input_file)
    if not base:
        base = _cross_platform_basename(bin_path)

    out_dir_override = get_output_dir(args)
    out_dir = out_dir_override

    attr_arrays = {}
    dim = len(ATTR_NAMES)
    for i, name in enumerate(ATTR_NAMES):
        u_one_hot = [0.0] * dim
        u_one_hot[i] = 1.0
        out_file = f"{base}_features_map_{name}.json"
        fmap, _ = build_and_save_features_map_for_u(
            pcs, blocks, func_of_bb, u_one_hot, out_file,
            out_dir_override=out_dir_override,
        )
        attr_arrays[name] = fmap

    validate_exported_maps(attr_arrays, pcs)

    merged_path = os.path.join(out_dir, f"{base}_features_map.json")
    with open(merged_path, "w") as f:
        json.dump(attr_arrays, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved merged 16-key features_map -> {merged_path}")

    out_map, out_dbg = build_and_save_features_map(
        pcs, CFG, blocks, func_of_bb, reachable_edges,
        out_dir_override=out_dir_override, base_override=base,
    )

    execution = _build_execution_metadata(args, bin_path, out_dir)
    execution["output_basename"] = base
    schema_path = save_schema_json(out_dir, base, execution=execution)

    time_end = time.time()
    print(f"\n[+] DONE.")
    print(f"    Schema version : {FEATURE_SCHEMA_VERSION}")
    print(f"    Feature dims   : {len(ATTR_NAMES)}")
    print(f"    Blocks         : {len(blocks)}")
    print(f"    Merged map     : {merged_path}")
    print(f"    Default map    : {out_map}")
    print(f"    Debug          : {out_dbg}")
    print(f"    Schema         : {schema_path}")
    print(f"    APageRank      : {'enabled' if USE_APAGERANK else 'disabled'}")
    print(f"    Mode           : {execution['mode']}")
    print(f"    Time           : {(time_end - time_start):.2f}s")


# ============================== MAIN ==============================
def main(args=None):
    if args is None:
        # When invoked by IDA via the -S flag, sys.argv often contains IDA's
        # own arguments (script path, IDB, etc.) which are not valid for our
        # argparse. Detect that case and use an empty arg list instead.
        if _detect_inside_ida():
            args = parse_cli_args([])
        else:
            args = parse_cli_args(sys.argv[1:])

    bootstrap_ida_environment(args)

    try:
        return run_extraction(args)
    finally:
        cleanup_ida_environment()


if __name__ == "__main__":
    main()
