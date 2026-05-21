# -*- coding: utf-8 -*-
"""
Build {binary}_features_map.json aligned to sancov pc-table,
USING ONLY the target-binary-exclusive CFG/CG (reachable from LLVMFuzzerTestOneInput).

Canonical 16-feature basic-block static extractor (schema v4).

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
import hashlib
import os
import random
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

# ---- Schema v4: canonical 16-dim non-negative feature set ----
FEATURE_SCHEMA_VERSION = 4
NORMALIZATION_EPS = 1e-6

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
    """Coerce ``x`` to a finite float, returning 0.0 on failure.

    Accepts ints/floats/strings; non-finite (NaN/inf) values become 0.0.
    Used pervasively by the ACFG statistics / Voronoi aggregation pipeline.
    """
    try:
        v = float(x)
    except Exception:
        return 0.0
    if not math.isfinite(v):
        return 0.0
    return v

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
def normalization_metadata():
    return {
        "default": "nonnegative_log1p_minmax_v1",
        "range": "[0, 1]",
        "eps": NORMALIZATION_EPS,
        "binary_features": sorted(RAW_BINARY_FEATURES),
        "apagerank": "removed",
        "voronoi_aggregation": "sum",
    }


def _normalize_nonnegative_log1p_minmax_feature(name, raw_values):
    xs = [max(0.0, finite_or_zero(x)) for x in raw_values]

    if name in RAW_BINARY_FEATURES:
        return [1.0 if x > 0.0 else 0.0 for x in xs]

    ts = [math.log1p(x) for x in xs]
    if not ts:
        return []

    lo = min(ts)
    hi = max(ts)
    span = hi - lo
    if span <= NORMALIZATION_EPS:
        return [0.0 for _ in ts]

    out = []
    for t in ts:
        v = (t - lo) / span
        v = min(1.0, max(0.0, finite_or_zero(v)))
        out.append(v)
    return out


def normalize_blocks(blocks):
    if not blocks:
        return

    bblist = list(blocks.values())

    for name in ATTR_NAMES:
        raw_values = [b.get_raw_attr(name) for b in bblist]
        norm_values = _normalize_nonnegative_log1p_minmax_feature(name, raw_values)

        for b, v in zip(bblist, norm_values):
            fv = float(v)
            if not math.isfinite(fv):
                raise RuntimeError(f"non-finite normalized feature: {name}={v}")
            if fv < 0.0:
                raise RuntimeError(f"negative normalized feature forbidden: {name}={v}")
            if fv > 1.0 + NORMALIZATION_EPS:
                raise RuntimeError(f"normalized feature exceeds [0,1]: {name}={v}")
            b.set_norm_attr(name, fv)

# ======================= SANCOV PC-TABLE =======================
def collect_pcs_aligned_with_counters():
    """Parse the libFuzzer pc-table into a list aligned with __sancov_cntrs.

    The pc-table is a fixed-stride array of ``(pc, flags)`` pairs (16 bytes
    each on 64-bit), one entry per counter byte. The list this function
    returns has length ``len(__sancov_cntrs)`` and is indexed by sancov
    index. Any PC slot that cannot be parsed (e.g. IDA truncates the
    segment or a PC sits in an unexpected section such as ``.text.startup``)
    is recorded as ``0`` so downstream code sees an unmapped sancov site
    instead of dropping the index and shifting the whole array.
    """
    pcs_start, pcs_end = get_seg_bounds('__sancov_pcs')
    cnt_start, cnt_end = get_seg_bounds('__sancov_cntrs')
    if pcs_start is None or cnt_start is None:
        raise RuntimeError('Could not find __sancov_pcs or __sancov_cntrs segments')

    target_count = int(cnt_end - cnt_start)
    if target_count <= 0:
        raise RuntimeError('__sancov_cntrs length is 0')

    pcs = []
    ea = pcs_start
    # Fixed 16-byte stride is the canonical pc-table layout. The previous
    # variable-stride heuristic produced off-by-N truncation when IDA's
    # reported segment was 8 bytes short of the real section size, or when
    # one of the PCs lived in e.g. ``.text.startup``.
    while ea + 16 <= pcs_end and len(pcs) < target_count:
        q = read_qword_safe(ea)
        pcs.append(q if q is not None else 0)
        ea += 16

    if len(pcs) < target_count:
        log.warning(
            f"Only parsed {len(pcs)} PCs from __sancov_pcs, fewer than counters={target_count}; "
            f"padding remaining slots with 0 to keep sancov-index alignment"
        )
        while len(pcs) < target_count:
            pcs.append(0)
    elif len(pcs) > target_count:
        log.warning(
            f"Parsed {len(pcs)} PCs from __sancov_pcs, more than counters={target_count}; truncating"
        )

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
        # Use a dedicated Random instance so the global ``random`` state is
        # untouched (centrality sampling must not perturb the deterministic
        # random6 baseline selection).
        rng = random.Random(CENTRALITY_SAMPLE_SEED)
        sample_nodes = rng.sample(nodes, min(CENTRALITY_SAMPLE_MAX, N))

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

# ======================= ACFG CONSTRUCTION HELPERS =======================
# All helpers below operate on plain Python data (CFG dicts, ``blocks``
# mapping ``ea -> BBlock``, schema feature specs). They contain no IDA
# dependency so they can be exercised by ``--self-test-acfg-stats``.

def build_acfg_index(blocks):
    """Assign deterministic stable ACFG node indexes.

    Sorted by basic-block start address so indexes are reproducible
    across runs and binaries.

    Returns ``(node_order, node_index)`` where ``node_order`` is a list
    of basic-block start addresses and ``node_index[ea] = i``.
    """
    node_order = sorted(blocks.keys())
    node_index = {ea: i for i, ea in enumerate(node_order)}
    return node_order, node_index


def build_acfg_adjacency(cfg, node_index, edge_mode="directed"):
    """Build the ACFG adjacency used by Moran's I.

    For CFG edge ``u -> v`` (both endpoints in ``node_index``):

      * ``directed``   -> ``w_uv = 1``, ``w_vu = 0``
      * ``undirected`` -> ``w_uv = 1``, ``w_vu = 1`` (symmetrized)

    Self-loops are dropped.
    """
    adj = defaultdict(set)
    for src, dsts in cfg.items():
        if src not in node_index:
            continue
        i = node_index[src]
        for dst in dsts:
            if dst not in node_index:
                continue
            if src == dst:
                continue
            k = node_index[dst]
            adj[i].add(k)
            if edge_mode == "undirected":
                adj[k].add(i)
    return {i: sorted(vs) for i, vs in adj.items()}


def build_voronoi_adjacency(cfg, node_index):
    """Directed-successor adjacency for Voronoi region assignment.

    Only includes the forward CFG edge ``u -> v`` (never the reverse).
    Self-loops are dropped.
    """
    adj = defaultdict(set)
    for src, dsts in cfg.items():
        if src not in node_index:
            continue
        i = node_index[src]
        for dst in dsts:
            if dst not in node_index:
                continue
            if src == dst:
                continue
            adj[i].add(node_index[dst])
    return {i: sorted(vs) for i, vs in adj.items()}


# ======================= STATISTICS HELPERS =======================
def get_acfg_feature_signal(blocks, node_order, feature_name, signal_source="norm"):
    """Return the per-node feature signal list in ACFG node order."""
    values = []
    for ea in node_order:
        block = blocks[ea]
        if signal_source == "raw":
            value = block.raw_attrs.get(feature_name, 0.0)
        else:
            value = block.norm_attrs.get(feature_name, 0.0)
        values.append(finite_or_zero(value))
    return values


def to_strength_signal(xs, eps=1e-8):
    """Convert raw/normalized values to non-negative strength ``z``.

    Near-zero magnitudes (|x| <= eps) collapse to 0 to suppress
    floating-point noise.
    """
    zs = []
    for x in xs:
        v = abs(finite_or_zero(x))
        if v <= eps:
            v = 0.0
        zs.append(v)
    return zs


def average_ranks(values):
    """1-based average ranks with tie-handling. All ranks are finite."""
    n = len(values)
    if n == 0:
        return []
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    pos = 0
    while pos < n:
        end = pos + 1
        while end < n and values[order[end]] == values[order[pos]]:
            end += 1
        avg_rank = (pos + 1 + end) / 2.0
        for q in range(pos, end):
            ranks[order[q]] = avg_rank
        pos = end
    return ranks


def moran_i(y, adj):
    """Compute Moran's I given signal ``y`` and adjacency ``adj``.

    ``adj`` is ``{i: [neighbors...]}``. Self-loops must already be removed.
    Returns 0 for degenerate graphs (empty / no edges / constant signal).
    Negative values are NOT clamped.
    """
    n = len(y)
    if n == 0:
        return 0.0
    s0 = 0
    for vs in adj.values():
        s0 += len(vs)
    if s0 <= 0:
        return 0.0
    mean_y = sum(y) / float(n)
    denom = sum((v - mean_y) ** 2 for v in y)
    if denom <= 1e-12:
        return 0.0
    num = 0.0
    for i, neighs in adj.items():
        yi = y[i] - mean_y
        for k in neighs:
            num += yi * (y[k] - mean_y)
    result = (float(n) / float(s0)) * (num / denom)
    return finite_or_zero(result)


def gini_coefficient(values):
    """Sorted-form Gini coefficient on non-negative strength values.

    Returns 0 for empty input or all-zero strength. Small negative
    artefacts close to zero are clamped to 0; otherwise the raw result
    is returned (typically within ``[0, 1]``).
    """
    xs = sorted(max(0.0, finite_or_zero(v)) for v in values)
    n = len(xs)
    if n == 0:
        return 0.0
    total = sum(xs)
    if total <= 1e-12:
        return 0.0
    weighted = 0.0
    for idx, val in enumerate(xs, start=1):
        weighted += idx * val
    g = (2.0 * weighted) / (n * total) - (n + 1.0) / n
    if -1e-12 < g < 0.0:
        g = 0.0
    return finite_or_zero(g)


def compute_acfg_feature_statistics(blocks, schema_features, node_order, adj,
                                     signal_source="norm", eps=1e-8,
                                     edge_mode="directed"):
    """Per-feature MoranI(rank(z)) / Gini(z) / signed ACFG-RDS.

    Returns ``(stats, ranked)`` where ``stats`` follows schema order and
    ``ranked`` sorts ``stats`` by ``abs(acfg_rds)`` descending and adds
    ``rank_by_abs_acfg_rds``.
    """
    n_nodes = len(node_order)
    n_edges = sum(len(vs) for vs in adj.values())

    stats = []
    for spec in schema_features:
        feature_id = spec["id"]
        feature_name = spec["name"]
        group = spec.get("group")

        x = get_acfg_feature_signal(blocks, node_order, feature_name, signal_source)
        z = to_strength_signal(x, eps)
        r = average_ranks(z)

        mi = moran_i(r, adj)
        g = gini_coefficient(z)
        rds = finite_or_zero(mi * g)

        active_count = sum(1 for v in z if v > 0.0)
        active_rate = (active_count / float(n_nodes)) if n_nodes > 0 else 0.0

        if rds > 0:
            sign = "positive"
        elif rds < 0:
            sign = "negative"
        else:
            sign = "zero"

        stats.append({
            "feature_id": feature_id,
            "feature_name": feature_name,
            "group": group,
            "n_blocks": n_nodes,
            "n_edges": n_edges,
            "edge_mode": edge_mode,
            "active_count": active_count,
            "active_rate": finite_or_zero(active_rate),
            "moran_i_rank_strength": finite_or_zero(mi),
            "gini_strength": finite_or_zero(g),
            "acfg_rds": rds,
            "abs_acfg_rds": finite_or_zero(abs(rds)),
            "sign": sign,
        })

    # Rank by abs(acfg_rds) descending; tie-break uses schema order so
    # the resulting order is fully deterministic (plan decision 4).
    ranked = rank_acfg_stats_by_abs(stats, schema_features)
    # Also annotate every row with ``rank_by_gini`` so the Gini-only
    # selection view does not have to recompute it later. Rows are shared
    # dicts, so this propagates to ``stats``, ``ranked`` and any other
    # downstream view by mutation.
    rank_acfg_stats_by_gini(stats, schema_features)
    return stats, ranked


def rank_acfg_stats_by_abs(stats, schema_features):
    """Sort ``stats`` by ``abs_acfg_rds`` descending with schema tie-break.

    Plan decision 4: when two rows have identical ``abs_acfg_rds``, the
    one whose ``feature_id`` appears earlier in ``schema_features`` wins.
    Rows whose ``feature_id`` is not in the schema sort after every
    schema feature, preserving their relative order.

    The function annotates each row in place with ``rank_by_abs_acfg_rds``
    (1-based) and returns a new list referencing the same dicts in ranked
    order. Negative ``acfg_rds`` rows are not filtered: ranking depends
    only on magnitude, never on sign.
    """
    schema_index = {
        spec["id"]: idx for idx, spec in enumerate(schema_features)
    }
    ranked = sorted(
        stats,
        key=lambda row: (
            -row["abs_acfg_rds"],
            schema_index.get(row["feature_id"], 10**9),
        ),
    )
    for idx, row in enumerate(ranked, start=1):
        row["rank_by_abs_acfg_rds"] = idx
    return ranked


def vec_mask_from_feature_ids(schema_features, selected_feature_ids):
    """Build a 0/1 string of len(schema_features) marking selected ids."""
    selected = set(selected_feature_ids)
    return "".join("1" if spec["id"] in selected else "0" for spec in schema_features)


# ============== SELECTION-VIEW HELPERS (ABLATION SUPPORT) ==============
# These helpers back the three feature-selection views exposed by the
# statistics JSON for ablation experiments (plan
# ``bofuzz_features_selection_ablation_plan.md``):
#
#   top6_abs_acfg_rds  -> six features with largest ``abs(acfg_rds)``
#   top6_gini          -> six features with largest ``gini_strength``
#   random6            -> six features sampled uniformly without replacement
#                         from all schema features, deterministically seeded
#
# No selection view changes BOFuzz runtime behavior automatically; users must
# explicitly pass the desired vec-mask to the fuzzer.
def build_schema_index(schema_features):
    """Map ``feature_id`` -> position in schema order.

    Used as the deterministic tie-break for every ranking helper so two rows
    with identical primary keys always resolve to the schema-declared order
    (``I00 < I01 < ... < S07``).
    """
    return {spec["id"]: idx for idx, spec in enumerate(schema_features)}


def rank_acfg_stats_by_gini(stats, schema_features):
    """Sort ``stats`` by ``gini_strength`` descending with schema tie-break.

    Mirrors ``rank_acfg_stats_by_abs`` but ranks by Gini concentration alone.
    Annotates each row in place with ``rank_by_gini`` (1-based) and returns
    a new list referencing the same dicts in Gini-ranked order. No filtering
    is applied: sign, feature group, and zero ``acfg_rds`` are all ignored.
    """
    schema_index = build_schema_index(schema_features)
    ranked = sorted(
        stats,
        key=lambda row: (
            -float(row.get("gini_strength", 0.0)),
            schema_index.get(row["feature_id"], 10**9),
        ),
    )
    for idx, row in enumerate(ranked, start=1):
        row["rank_by_gini"] = idx
    return ranked


def stable_target_seed(target_name, base_seed):
    """Derive a deterministic per-target seed.

    Uses SHA-256 over ``"<target_name>:<base_seed>"`` and returns the first
    eight bytes as a non-negative integer. Python's built-in ``hash()`` is
    randomized across processes and is NOT used here.
    """
    payload = "{}:{}".format(target_name, int(base_seed)).encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def select_random6_features(schema_features, target_name, base_seed):
    """Pick six schema features uniformly at random without replacement.

    Sampling pool is the *entire* schema (no score / sign / group filtering).
    The returned ID order preserves the random draw order; downstream
    ``vec_mask`` generation re-orders selection into schema order, which is
    the contract documented in the plan.
    """
    if len(schema_features) < 6:
        raise RuntimeError(
            "random6 requires at least 6 schema features, got {}".format(
                len(schema_features)
            )
        )
    derived_seed = stable_target_seed(target_name, base_seed)
    rng = random.Random(derived_seed)
    indices = list(range(len(schema_features)))
    selected_indices = rng.sample(indices, 6)
    selected_ids = [schema_features[i]["id"] for i in selected_indices]
    return selected_ids, derived_seed


def make_feature_selection_payload(selection_rule, rows, schema_features):
    """Build the per-view JSON object emitted under each selection view.

    Each entry in ``feature_details`` mirrors the corresponding row from
    ``statistics["features"]`` and exposes the metrics needed for downstream
    interpretation: signed ``acfg_rds``, ``abs_acfg_rds``, ``sign``, both
    rank annotations and ``moran_i_rank_strength``.
    """
    feature_ids = [row["feature_id"] for row in rows]
    return {
        "selection_rule": selection_rule,
        "vec_mask": vec_mask_from_feature_ids(schema_features, feature_ids),
        "features": feature_ids,
        "feature_details": [
            {
                "feature_id": row["feature_id"],
                "feature_name": row.get("feature_name"),
                "group": row.get("group"),
                "acfg_rds": row.get("acfg_rds"),
                "abs_acfg_rds": row.get("abs_acfg_rds"),
                "sign": row.get("sign"),
                "rank_by_abs_acfg_rds": row.get("rank_by_abs_acfg_rds"),
                "gini_strength": row.get("gini_strength"),
                "rank_by_gini": row.get("rank_by_gini"),
                "moran_i_rank_strength": row.get("moran_i_rank_strength"),
            }
            for row in rows
        ],
    }


def _selection_overlap_count(a, b):
    """Cardinality of the intersection of two feature-id collections."""
    return len(set(a) & set(b))


# ======================= ACFG VORONOI HELPERS =======================
def build_sancov_seed_nodes(pcs, bb_cache, blocks, node_index):
    """Map sancov PCs to ACFG seed nodes.

    Returns a list of seed records, one per sancov index, with
    ``node_index = None`` when the PC's containing basic block is not
    a target-only ACFG block (or no block was found at all).
    """
    seeds = []
    for sancov_index, pc in enumerate(pcs):
        bb = bb_cache.find_block(pc)
        if bb is None:
            seeds.append({
                "sancov_index": sancov_index,
                "pc": hex(pc),
                "bb_start": None,
                "node_index": None,
                "note": "no_bb",
            })
            continue
        start = bb.start_ea
        if start in node_index:
            seeds.append({
                "sancov_index": sancov_index,
                "pc": hex(pc),
                "bb_start": hex(start),
                "node_index": node_index[start],
            })
        else:
            seeds.append({
                "sancov_index": sancov_index,
                "pc": hex(pc),
                "bb_start": hex(start),
                "node_index": None,
                "note": "non_target",
            })
    return seeds


def validate_unique_sancov_seed_nodes(seeds):
    """Fail fast if two sancov sites map to the same ACFG node.

    Plan decision 12: duplicate sancov seeds are an instrumentation
    error and must not be silently merged.
    """
    by_node = {}
    for seed in seeds:
        node = seed.get("node_index")
        if node is None:
            continue
        by_node.setdefault(node, []).append(seed)

    duplicates = {node: ss for node, ss in by_node.items() if len(ss) > 1}
    if not duplicates:
        return

    lines = [
        "BOFuzz ACFG Voronoi error: duplicate sancov seeds map to the same ACFG block.",
    ]
    for node, ss in sorted(duplicates.items()):
        bb_start = ss[0].get("bb_start")
        lines.append(f"  node_index={node} bb_start={bb_start}")
        for seed in ss:
            lines.append(
                "    sancov_index={} pc={} bb_start={}".format(
                    seed["sancov_index"], seed.get("pc"), seed.get("bb_start"),
                )
            )
    lines.append(
        "This indicates invalid or ambiguous instrumentation. "
        "Please debug sancov PC mapping."
    )
    raise RuntimeError("\n".join(lines))


def build_acfg_voronoi_regions(node_count, seeds, voronoi_adj):
    """Multi-source directed-successor Voronoi partition.

    Tie-break: smaller sancov_index claims the node. Done by processing
    BFS layer-by-layer and taking the minimum candidate owner per node
    within a layer. Each node is finalized at the first distance it is
    reached, so layer ordering yields deterministic regions.

    Returns ``(regions_by_sancov_index, node_assignment, unassigned)``.
    """
    owner = [None] * node_count
    distance = [None] * node_count

    seed_pairs = []
    for seed in seeds:
        n = seed.get("node_index")
        if n is None:
            continue
        if not (0 <= n < node_count):
            continue
        seed_pairs.append((seed["sancov_index"], n))

    # Initialize layer 0 in ascending sancov_index order so the smallest
    # index claims any shared node first. Duplicates should already have
    # been rejected by ``validate_unique_sancov_seed_nodes``.
    current_layer = []
    for si, n in sorted(seed_pairs, key=lambda x: x[0]):
        if owner[n] is None:
            owner[n] = si
            distance[n] = 0
            current_layer.append(n)

    d = 0
    while current_layer:
        next_layer_owner = {}
        for u in current_layer:
            ou = owner[u]
            for v in voronoi_adj.get(u, ()):
                if owner[v] is not None:
                    continue
                existing = next_layer_owner.get(v)
                if existing is None or ou < existing:
                    next_layer_owner[v] = ou

        new_layer = []
        for v, ow in next_layer_owner.items():
            owner[v] = ow
            distance[v] = d + 1
            new_layer.append(v)

        current_layer = new_layer
        d += 1

    regions_by_sancov = defaultdict(list)
    node_assignment = {}
    unassigned = []
    for n in range(node_count):
        if owner[n] is None:
            unassigned.append(n)
        else:
            regions_by_sancov[owner[n]].append(n)
            node_assignment[n] = {"owner": owner[n], "distance": distance[n]}

    return dict(regions_by_sancov), node_assignment, unassigned


def aggregate_voronoi_region(values_by_node, region_nodes, node_assignment=None, gamma=None):
    """Sum aggregation over one Voronoi region.

    Block-level values are already normalized into ``[0, 1]``. The sum rewards
    larger regions; callers re-normalize the sancov-level arrays afterward.
    """
    if not region_nodes:
        return 0.0
    total = 0.0
    for node_idx in region_nodes:
        v = max(0.0, finite_or_zero(values_by_node.get(node_idx, 0.0)))
        total += v
    if not math.isfinite(total) or total < 0.0:
        raise RuntimeError(f"invalid Voronoi sum aggregation value: {total}")
    return total


def build_voronoi_runtime_feature_arrays(blocks, node_order, schema_features,
                                          seeds, regions_by_sancov,
                                          node_assignment, gamma,
                                          signal_source="norm"):
    """Per-feature, sancov-aligned arrays produced by Voronoi aggregation.

    Output shape: ``{feature_name: [v0, v1, ..., v_{S-1}]}`` where S is
    ``len(seeds)`` (i.e. ``len(sancov_sites)``). Unmapped sancov sites
    or unmapped regions emit ``0.0``.
    """
    n_sancov = len(seeds)
    feature_arrays = {}

    seed_by_index = [None] * n_sancov
    for seed in seeds:
        si = seed["sancov_index"]
        if 0 <= si < n_sancov:
            seed_by_index[si] = seed

    for spec in schema_features:
        feature_name = spec["name"]
        # Build per-node value map once per feature.
        values_by_node = {}
        for node_idx, ea in enumerate(node_order):
            block = blocks[ea]
            if signal_source == "raw":
                val = block.raw_attrs.get(feature_name, 0.0)
            else:
                val = block.norm_attrs.get(feature_name, 0.0)
            values_by_node[node_idx] = finite_or_zero(val)

        arr = []
        for sancov_index in range(n_sancov):
            seed = seed_by_index[sancov_index]
            if seed is None or seed.get("node_index") is None:
                arr.append(0.0)
                continue
            region = regions_by_sancov.get(sancov_index, [])
            if not region:
                # Empty region: fall back to direct seed-node value.
                arr.append(finite_or_zero(values_by_node.get(seed["node_index"], 0.0)))
                continue
            arr.append(aggregate_voronoi_region(
                values_by_node, region, node_assignment, gamma,
            ))
        feature_arrays[feature_name] = _normalize_nonnegative_log1p_minmax_feature(
            feature_name, arr,
        )

    return feature_arrays


# ======================= ACFG / STATISTICS / VORONOI EXPORTERS =======================
def save_acfg_json(out_dir, base, target_name, blocks, node_order,
                    node_index, adj_directed, signal_source, edge_mode,
                    voronoi_distance, eps):
    """Emit ``<base>_acfg.json`` (schema v3)."""
    nodes = []
    for ea in node_order:
        b = blocks[ea]
        nodes.append({
            "index": node_index[ea],
            "bb_start": hex(ea),
            "func": hex(b.func_ea),
            "attrs_raw": {k: finite_or_zero(v) for k, v in b.raw_attrs.items()},
            "attrs_norm": {k: finite_or_zero(v) for k, v in b.norm_attrs.items()},
        })
    edges = []
    for i in sorted(adj_directed.keys()):
        for k in adj_directed[i]:
            edges.append([i, k])

    payload = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "kind": "bofuzz-acfg-v1",
        "target": target_name,
        "signal_source": signal_source,
        "moran_edge_mode": edge_mode,
        "voronoi_distance": voronoi_distance,
        "eps": eps,
        "n_nodes": len(nodes),
        "n_edges": len(edges),
        "nodes": nodes,
        "edges": edges,
    }
    out_path = os.path.join(out_dir, f"{base}_acfg.json")
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved ACFG -> {out_path}")
    return out_path


def save_acfg_voronoi_json(out_dir, base, target_name, seeds,
                            regions_by_sancov, node_assignment,
                            unassigned_nodes, n_nodes, gamma,
                            distance_mode, aggregation_mode):
    """Emit ``<base>_acfg_voronoi.json`` (schema v3)."""
    regions = []
    n_valid_seeds = 0
    n_unmapped = 0
    assigned_nodes = 0
    for seed in seeds:
        node = seed.get("node_index")
        if node is None:
            n_unmapped += 1
            continue
        n_valid_seeds += 1
        si = seed["sancov_index"]
        region = regions_by_sancov.get(si, [])
        assigned_nodes += len(region)
        if region:
            distances = [node_assignment[n]["distance"] for n in region]
            max_d = max(distances)
            mean_d = sum(distances) / float(len(distances))
        else:
            max_d = 0
            mean_d = 0.0
        regions.append({
            "sancov_index": si,
            "pc": seed.get("pc"),
            "seed_node": node,
            "region_size": len(region),
            "max_distance": max_d,
            "mean_distance": finite_or_zero(mean_d),
            "nodes": region,
        })

    unassigned_ratio = (len(unassigned_nodes) / float(n_nodes)) if n_nodes > 0 else 0.0
    payload = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "kind": "bofuzz-acfg-voronoi-v1",
        "target": target_name,
        "distance_mode": distance_mode,
        "aggregation_mode": aggregation_mode,
        "gamma": gamma,
        "n_acfg_nodes": n_nodes,
        "n_sancov_sites": len(seeds),
        "valid_seed_nodes": n_valid_seeds,
        "unmapped_sancov_sites": n_unmapped,
        "assigned_nodes": assigned_nodes,
        "unassigned_nodes": len(unassigned_nodes),
        "unassigned_node_ratio": finite_or_zero(unassigned_ratio),
        "regions": regions,
    }
    out_path = os.path.join(out_dir, f"{base}_acfg_voronoi.json")
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved ACFG Voronoi -> {out_path}")
    return out_path


def save_sancov_acfg_json(out_dir, base, target_name, sancov_seeds,
                           regions_by_sancov, node_assignment, acfg_adj):
    # Emit <base>_sancov_acfg.json for runtime frontier computation.
    n_sancov = len(sancov_seeds)
    successors = [set() for _ in range(n_sancov)]
    predecessors = [set() for _ in range(n_sancov)]

    def owner_sancov(node_idx):
        info = node_assignment.get(node_idx)
        if info is None:
            return None
        owner = info.get("owner")
        if owner is None or not (0 <= int(owner) < n_sancov):
            return None
        return int(owner)

    for u, vs in acfg_adj.items():
        su = owner_sancov(u)
        if su is None:
            continue
        for v in vs:
            sv = owner_sancov(v)
            if sv is None or sv == su:
                continue
            successors[su].add(sv)
            predecessors[sv].add(su)

    seed_by_index = {seed["sancov_index"]: seed for seed in sancov_seeds}
    nodes = []
    for sancov_index in range(n_sancov):
        seed = seed_by_index.get(sancov_index)
        if seed is None:
            continue
        node = seed.get("node_index")
        if node is None:
            continue
        nodes.append({
            "sancov_index": sancov_index,
            "pc": seed.get("pc"),
            "seed_node": node,
            "region_size": len(regions_by_sancov.get(sancov_index, [])),
        })

    payload = {
        "schema_version": 1,
        "kind": "bofuzz-sancov-acfg-v1",
        "target": target_name,
        "n_sancov_sites": n_sancov,
        "nodes": nodes,
        "successors": [sorted(vs) for vs in successors],
        "predecessors": [sorted(vs) for vs in predecessors],
    }

    if len(payload["successors"]) != n_sancov:
        raise RuntimeError("sancov ACFG successors length mismatch")
    if len(payload["predecessors"]) != n_sancov:
        raise RuntimeError("sancov ACFG predecessors length mismatch")

    out_path = os.path.join(out_dir, f"{base}_sancov_acfg.json")
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved sancov ACFG -> {out_path}")
    return out_path


def save_acfg_statistics_json(out_dir, base, target_name, schema_features,
                                ranked_stats, n_nodes, n_edges,
                                signal_source, edge_mode, eps,
                                runtime_map_meta,
                                random_feature_seed=0xFA1C4):
    """Emit ``<base>_statistics.json`` plus standalone vec-mask files.

    The statistics JSON exposes multiple feature-selection views for
    ablation experiments:

      * ``top6_abs_acfg_rds`` captures the full ACFG-RDS regional-guidance
        score (largest ``abs(acfg_rds)``).
      * ``top6_gini`` isolates feature-strength concentration without
        graph autocorrelation (largest ``gini_strength``).
      * ``random6`` is a deterministic random baseline sampled uniformly
        from all schema features.

    No view changes BOFuzz runtime behavior automatically; users must
    explicitly pass the desired vec-mask to BOFuzz. The legacy ``top4``
    view (largest ``abs(acfg_rds)``) is kept for backward compatibility
    with existing tooling. The ambiguous generic ``top6`` field is no
    longer emitted; consumers should pick an explicit selection view.

    Returns a dict with the statistics path, the per-view mask paths and
    the per-view selected rows.
    """
    # ``ranked_stats`` is the abs-ranked view; rebuild a schema-ordered
    # listing for the top-level ``features`` field while keeping shared
    # row dicts so every rank annotation propagates.
    rank_by_id = {row["feature_id"]: row for row in ranked_stats}
    features_in_schema_order = [
        rank_by_id[spec["id"]]
        for spec in schema_features
        if spec["id"] in rank_by_id
    ]

    # --- top6_abs_acfg_rds: first six by abs-RDS ranking ---------------
    top6_abs_rows = ranked_stats[:6]

    # --- top6_gini: first six by Gini-only ranking ---------------------
    # Recompute the Gini ranking here (cheap) so we never rely on a stale
    # ordering even if ``ranked_stats`` is mutated by the caller.
    gini_ranked = rank_acfg_stats_by_gini(ranked_stats, schema_features)
    top6_gini_rows = gini_ranked[:6]

    # --- random6: deterministic uniform sample without replacement ----
    stats_by_id = {row["feature_id"]: row for row in ranked_stats}
    random6_ids, derived_seed = select_random6_features(
        schema_features, target_name, random_feature_seed,
    )
    missing_random_ids = [fid for fid in random6_ids if fid not in stats_by_id]
    if missing_random_ids:
        raise RuntimeError(
            "random6 selected feature(s) {!r} not present in computed "
            "statistics; this indicates a schema/feature mismatch".format(
                missing_random_ids,
            )
        )
    random6_rows = [stats_by_id[fid] for fid in random6_ids]

    # Legacy top4 (out of scope of the ablation plan but still emitted for
    # downstream tools that depend on it).
    top4_rows = ranked_stats[:4]
    top4_ids = [row["feature_id"] for row in top4_rows]
    top4_mask = vec_mask_from_feature_ids(schema_features, top4_ids)

    top6_abs_payload = make_feature_selection_payload(
        "largest abs(acfg_rds)", top6_abs_rows, schema_features,
    )
    top6_gini_payload = make_feature_selection_payload(
        "largest gini_strength", top6_gini_rows, schema_features,
    )
    random6_payload = make_feature_selection_payload(
        "uniform random sample without replacement from all schema features",
        random6_rows,
        schema_features,
    )
    # Inject the deterministic seed metadata before the generic fields so
    # readers see provenance up-front.
    random6_seed_meta = {
        "random_feature_seed": "0x{:x}".format(int(random_feature_seed)),
        "random_feature_seed_int": int(random_feature_seed),
        "derived_seed": int(derived_seed),
    }
    random6_payload = {
        "selection_rule": random6_payload["selection_rule"],
        **random6_seed_meta,
        "vec_mask": random6_payload["vec_mask"],
        "features": random6_payload["features"],
        "feature_details": random6_payload["feature_details"],
    }

    selection_view_overlap = {
        "top6_abs_vs_gini": _selection_overlap_count(
            top6_abs_payload["features"], top6_gini_payload["features"],
        ),
        "top6_abs_vs_random6": _selection_overlap_count(
            top6_abs_payload["features"], random6_payload["features"],
        ),
        "top6_gini_vs_random6": _selection_overlap_count(
            top6_gini_payload["features"], random6_payload["features"],
        ),
    }

    payload = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "kind": "bofuzz-acfg-statistics-v1",
        "target": target_name,
        "signal_source": signal_source,
        "moran_edge_mode": edge_mode,
        "eps": eps,
        "ranking_metric": "abs_acfg_rds",
        "ranking_semantics": (
            "features are ranked by absolute signed ACFG-RDS; "
            "sign is preserved for interpretation"
        ),
        "negative_scores_allowed_in_topk": True,
        "selection_views": {
            "available": [
                "top6_abs_acfg_rds",
                "top6_gini",
                "random6",
            ],
            "runtime_default": None,
            "runtime_semantics": (
                "No selection view changes runtime behavior automatically; "
                "BOFuzz uses the vec-mask explicitly passed by the user."
            ),
            "analysis_note": (
                "top6_abs_acfg_rds, top6_gini, and random6 are emitted "
                "for ablation experiments."
            ),
        },
        "selection_view_overlap": selection_view_overlap,
        "n_blocks": n_nodes,
        "n_edges": n_edges,
        "features": features_in_schema_order,
        "top4": {
            "selection_rule": "largest abs(acfg_rds)",
            "vec_mask": top4_mask,
            "features": top4_ids,
            "feature_details": [
                {
                    "feature_id": row["feature_id"],
                    "feature_name": row["feature_name"],
                    "acfg_rds": row["acfg_rds"],
                    "abs_acfg_rds": row["abs_acfg_rds"],
                    "sign": row["sign"],
                    "rank_by_abs_acfg_rds": row["rank_by_abs_acfg_rds"],
                }
                for row in top4_rows
            ],
        },
        "top6_abs_acfg_rds": top6_abs_payload,
        "top6_gini": top6_gini_payload,
        "random6": random6_payload,
        "runtime_map_aggregation": runtime_map_meta,
    }
    stats_path = os.path.join(out_dir, f"{base}_statistics.json")
    with open(stats_path, "w") as f:
        json.dump(payload, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved ACFG statistics -> {stats_path}")

    top4_path = os.path.join(out_dir, f"{base}_acfg_rds_top4_vec_mask.txt")
    with open(top4_path, "w") as f:
        f.write(top4_mask + "\n")

    top6_abs_path = os.path.join(
        out_dir, f"{base}_top6_abs_acfg_rds_vec_mask.txt",
    )
    with open(top6_abs_path, "w") as f:
        f.write(top6_abs_payload["vec_mask"] + "\n")

    top6_gini_path = os.path.join(out_dir, f"{base}_top6_gini_vec_mask.txt")
    with open(top6_gini_path, "w") as f:
        f.write(top6_gini_payload["vec_mask"] + "\n")

    random6_path = os.path.join(out_dir, f"{base}_random6_vec_mask.txt")
    with open(random6_path, "w") as f:
        f.write(random6_payload["vec_mask"] + "\n")

    if VERBOSE:
        print(f"[+] Saved top4 vec mask           -> {top4_path}")
        print(f"[+] Saved top6_abs_acfg_rds mask  -> {top6_abs_path}")
        print(f"[+] Saved top6_gini mask          -> {top6_gini_path}")
        print(f"[+] Saved random6 mask            -> {random6_path}")

    return {
        "stats_path": stats_path,
        "top4_mask_path": top4_path,
        "top6_abs_acfg_rds_mask_path": top6_abs_path,
        "top6_gini_mask_path": top6_gini_path,
        "random6_mask_path": random6_path,
        "top4_rows": top4_rows,
        "top6_abs_acfg_rds_rows": top6_abs_rows,
        "top6_gini_rows": top6_gini_rows,
        "random6_rows": random6_rows,
        "random6_derived_seed": derived_seed,
    }


class _MockBlock(object):
    """Minimal BBlock stand-in for ``--self-test-acfg-stats``."""
    __slots__ = ("func_ea", "addr", "raw_attrs", "norm_attrs", "debug")

    def __init__(self, addr, raw=None, norm=None):
        self.func_ea = 0
        self.addr = addr
        self.raw_attrs = dict(raw or {})
        self.norm_attrs = dict(norm or {})
        self.debug = {}


def _approx(a, b, tol=1e-9):
    return abs(float(a) - float(b)) <= tol


def run_acfg_self_tests():
    """Pure-Python self-tests for ACFG statistics and Voronoi aggregation.

    Implements every case in plan section 17. Returns 0 on success, raises
    AssertionError otherwise. Imports nothing from IDA so it runs from a
    plain ``python3`` invocation.
    """
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print(f"  PASS  {name}")
        else:
            print(f"  FAIL  {name}: {detail}")
            failures.append(name)

    print("[self-test] uniform values")
    z_uniform = [1.0, 1.0, 1.0, 1.0]
    g_uniform = gini_coefficient(z_uniform)
    check("gini(uniform) == 0", _approx(g_uniform, 0.0), f"got {g_uniform}")

    print("[self-test] concentrated values")
    z_concentrated = [0.0, 0.0, 0.0, 10.0]
    g_conc = gini_coefficient(z_concentrated)
    check("gini(concentrated) > 0", g_conc > 0.0, f"got {g_conc}")
    # Closed-form: 2*(4*10)/(4*10) - (4+1)/4 = 2 - 1.25 = 0.75
    check("gini(concentrated) == 0.75", _approx(g_conc, 0.75), f"got {g_conc}")

    print("[self-test] all-zero strength")
    g_zero = gini_coefficient([0.0, 0.0, 0.0])
    mi_zero = moran_i([0.0, 0.0, 0.0], {0: [1], 1: [2]})
    check("gini(zero) == 0", _approx(g_zero, 0.0), f"got {g_zero}")
    check("moran(constant) == 0", _approx(mi_zero, 0.0), f"got {mi_zero}")

    print("[self-test] directed clustered chain 0->1->2->3 with z=[0,0,10,10]")
    chain_adj = {0: [1], 1: [2], 2: [3]}
    z = [0.0, 0.0, 10.0, 10.0]
    r = average_ranks(z)
    mi_clust = moran_i(r, chain_adj)
    check("MoranI(rank(z)) > 0 for clustered chain", mi_clust > 0.0,
          f"got {mi_clust}")

    print("[self-test] directed alternating chain 0->1->2->3 with z=[0,10,0,10]")
    z_alt = [0.0, 10.0, 0.0, 10.0]
    r_alt = average_ranks(z_alt)
    mi_alt = moran_i(r_alt, chain_adj)
    check("MoranI(rank(z)) < 0 for alternating chain", mi_alt < 0.0,
          f"got {mi_alt}")

    print("[self-test] non-finite inputs collapse to zero")
    bad_signal = [float("nan"), float("inf"), -float("inf"), "abc", None, 3.0]
    z_bad = to_strength_signal(bad_signal, eps=1e-8)
    check("to_strength_signal sanitizes NaN/inf/strings/None",
          z_bad == [0.0, 0.0, 0.0, 0.0, 0.0, 3.0],
          f"got {z_bad}")

    print("[self-test] rank ties use average rank")
    r_ties = average_ranks([10.0, 10.0, 20.0, 5.0])
    # Sorted: [5,10,10,20] => positions 1,2,3,4. Two 10's tie -> rank=2.5.
    # 5->1, 10->2.5, 10->2.5, 20->4
    check("average ranks correct for ties",
          [_approx(a, b) for a, b in zip(r_ties, [2.5, 2.5, 4.0, 1.0])] == [True]*4,
          f"got {r_ties}")

    print("[self-test] directed-successor Voronoi partition: 0->1->2->3->4 seeds {0,3}")
    cfg = {
        0x1000: {0x1010},
        0x1010: {0x1020},
        0x1020: {0x1030},
        0x1030: {0x1040},
        0x1040: set(),
    }
    blocks_fake = {ea: _MockBlock(ea) for ea in cfg}
    node_order_fake, node_index_fake = build_acfg_index(blocks_fake)
    expected_order = [0x1000, 0x1010, 0x1020, 0x1030, 0x1040]
    check("ACFG node order sorted by address",
          node_order_fake == expected_order,
          f"got {node_order_fake}")
    vor_adj = build_voronoi_adjacency(cfg, node_index_fake)
    seeds_fake = [
        {"sancov_index": 0, "pc": "0x1000",
         "bb_start": "0x1000", "node_index": node_index_fake[0x1000]},
        {"sancov_index": 1, "pc": "0x1030",
         "bb_start": "0x1030", "node_index": node_index_fake[0x1030]},
    ]
    regions, assign, unassigned = build_acfg_voronoi_regions(
        len(node_order_fake), seeds_fake, vor_adj,
    )
    # seed 0 owns nodes 0,1,2 ; seed 1 owns nodes 3,4 ; nothing unassigned.
    check("Voronoi region(seed=0) == [0,1,2]",
          regions.get(0) == [0, 1, 2], f"got {regions.get(0)}")
    check("Voronoi region(seed=1) == [3,4]",
          regions.get(1) == [3, 4], f"got {regions.get(1)}")
    check("no unassigned nodes in fully-reachable chain",
          unassigned == [], f"got {unassigned}")
    check("distance(seed=0, node=2) == 2",
          assign[2]["distance"] == 2,
          f"got {assign[2]['distance']}")
    check("distance(seed=1, node=4) == 1",
          assign[4]["distance"] == 1,
          f"got {assign[4]['distance']}")

    print("[self-test] directed-successor unassigned (0->1 and 2->3 with seed=0)")
    cfg2 = {0x2000: {0x2010}, 0x2010: set(), 0x2020: {0x2030}, 0x2030: set()}
    blocks_fake2 = {ea: _MockBlock(ea) for ea in cfg2}
    node_order_2, node_index_2 = build_acfg_index(blocks_fake2)
    vor_adj_2 = build_voronoi_adjacency(cfg2, node_index_2)
    seeds_2 = [
        {"sancov_index": 0, "pc": "0x2000",
         "bb_start": "0x2000", "node_index": node_index_2[0x2000]},
    ]
    regions2, assign2, unassigned2 = build_acfg_voronoi_regions(
        len(node_order_2), seeds_2, vor_adj_2,
    )
    check("seed=0 owns {0,1}",
          regions2.get(0) == [node_index_2[0x2000], node_index_2[0x2010]],
          f"got {regions2.get(0)}")
    check("nodes 2,3 unassigned (no incoming edge from seed)",
          sorted(unassigned2)
          == sorted([node_index_2[0x2020], node_index_2[0x2030]]),
          f"got {sorted(unassigned2)}")

    print("[self-test] Voronoi tie-break uses smaller sancov index")
    # 0 and 1 both reach node 2 at distance 1: 0->2 and 1->2.
    cfg_tie = {0xA: {0xC}, 0xB: {0xC}, 0xC: set()}
    blocks_tie = {ea: _MockBlock(ea) for ea in cfg_tie}
    n_order_t, n_idx_t = build_acfg_index(blocks_tie)
    vor_t = build_voronoi_adjacency(cfg_tie, n_idx_t)
    # Reverse sancov order on purpose: smaller index should still win.
    seeds_tie = [
        {"sancov_index": 7, "pc": "0xB",
         "bb_start": "0xB", "node_index": n_idx_t[0xB]},
        {"sancov_index": 3, "pc": "0xA",
         "bb_start": "0xA", "node_index": n_idx_t[0xA]},
    ]
    regions_t, assign_t, _u = build_acfg_voronoi_regions(
        len(n_order_t), seeds_tie, vor_t,
    )
    check("tie-break -> sancov 3 (smaller) owns node 0xC",
          assign_t[n_idx_t[0xC]]["owner"] == 3,
          f"got owner {assign_t[n_idx_t[0xC]]['owner']}")

    print("[self-test] duplicate sancov seed nodes are fatal")
    seeds_dup = [
        {"sancov_index": 17, "pc": "0x401232",
         "bb_start": "0x401230", "node_index": 0},
        {"sancov_index": 18, "pc": "0x401235",
         "bb_start": "0x401230", "node_index": 0},
    ]
    raised = False
    try:
        validate_unique_sancov_seed_nodes(seeds_dup)
    except RuntimeError as e:
        raised = True
        msg = str(e)
        check("duplicate error mentions both sancov_index",
              "sancov_index=17" in msg and "sancov_index=18" in msg,
              f"got message: {msg}")
        check("duplicate error mentions both pcs",
              "0x401232" in msg and "0x401235" in msg,
              f"got message: {msg}")
    check("duplicate seed mapping raises RuntimeError", raised,
          "no exception raised")

    print("[self-test] Voronoi sum aggregation")
    # seed=0, region={0:dist 0, 1:dist 1}, values={0:10, 1:20}
    # expected: 10 + 20 = 30
    values_by_node = {0: 10.0, 1: 20.0}
    region_nodes = [0, 1]
    node_assign_test = {
        0: {"owner": 0, "distance": 0},
        1: {"owner": 0, "distance": 1},
    }
    agg = aggregate_voronoi_region(
        values_by_node, region_nodes, node_assign_test, gamma=0.5,
    )
    check("aggregate_voronoi_region sums region values",
          _approx(agg, 30.0, tol=1e-9), f"got {agg}")

    print("[self-test] empty region falls back to zero")
    agg_empty = aggregate_voronoi_region({}, [], {}, gamma=0.5)
    check("empty region aggregation -> 0.0", _approx(agg_empty, 0.0),
          f"got {agg_empty}")

    print("[self-test] full feature statistics pipeline")
    # Reuse the 4-node chain with a synthetic feature that clusters strongly.
    blocks_pipe = {}
    eas = expected_order  # [0x1000, 0x1010, 0x1020, 0x1030, 0x1040]
    feat_values = [0.0, 0.0, 10.0, 10.0, 10.0]
    for ea, v in zip(eas, feat_values):
        blocks_pipe[ea] = _MockBlock(ea, norm={"test_feature": v})
    node_order_p, node_index_p = build_acfg_index(blocks_pipe)
    adj_p = build_acfg_adjacency(cfg, node_index_p, edge_mode="directed")
    schema = [{"id": "T00", "name": "test_feature", "group": "instruction"}]
    stats, ranked = compute_acfg_feature_statistics(
        blocks_pipe, schema, node_order_p, adj_p,
        signal_source="norm", eps=1e-8, edge_mode="directed",
    )
    check("stats list non-empty", len(stats) == 1, f"got {len(stats)}")
    check("ranked entry has rank_by_abs_acfg_rds",
          ranked[0].get("rank_by_abs_acfg_rds") == 1,
          f"got {ranked[0]}")
    check("clustered signal -> abs_acfg_rds > 0",
          ranked[0]["abs_acfg_rds"] > 0.0,
          f"got {ranked[0]['abs_acfg_rds']}")

    print("[self-test] vec_mask_from_feature_ids")
    schema16 = _build_runtime_schema()["features"]
    mask = vec_mask_from_feature_ids(schema16, ["I00", "I07", "S04", "S07"])
    check("vec_mask length == 16", len(mask) == 16, f"got len={len(mask)}")
    check("vec_mask has exactly four set bits", mask.count("1") == 4,
          f"got {mask} ones={mask.count('1')}")

    print("[self-test] directed mode covers Decision 2 weight convention")
    # Plan Decision 2: for CFG edge u->v, directed mode sets w_uv=1, w_vu=0.
    # Build adj from CFG edge 0->1 with edge_mode=directed/undirected and
    # confirm S0_directed==1, S0_undirected==2 (Moran's I itself is
    # invariant to symmetrization on simple CFGs; that is a property of
    # the formula, not a bug).
    cfg_one_edge = {0x100: {0x110}, 0x110: set()}
    blocks_oe = {ea: _MockBlock(ea) for ea in cfg_one_edge}
    _, ni_oe = build_acfg_index(blocks_oe)
    adj_dir = build_acfg_adjacency(cfg_one_edge, ni_oe, edge_mode="directed")
    adj_und = build_acfg_adjacency(cfg_one_edge, ni_oe, edge_mode="undirected")
    s0_dir = sum(len(v) for v in adj_dir.values())
    s0_und = sum(len(v) for v in adj_und.values())
    check("directed mode has S0=1 (single CFG edge)", s0_dir == 1,
          f"got {s0_dir}")
    check("undirected mode has S0=2 (symmetrized)", s0_und == 2,
          f"got {s0_und}")

    print("[self-test] Voronoi adjacency stays directed-only")
    # CFG edge u->v must produce u_idx -> v_idx only in Voronoi adjacency,
    # never the reverse (Decision 3).
    vor_oe = build_voronoi_adjacency(cfg_one_edge, ni_oe)
    src_idx = ni_oe[0x100]
    dst_idx = ni_oe[0x110]
    check("voronoi_adj[u] contains v",
          dst_idx in vor_oe.get(src_idx, []),
          f"got {vor_oe}")
    check("voronoi_adj[v] does NOT contain u",
          src_idx not in vor_oe.get(dst_idx, []),
          f"got {vor_oe}")

    # ------------------------------------------------------------------
    # Plan section 4 — abs(ACFG-RDS) ranking and top-k mask tests.
    # ------------------------------------------------------------------
    schema16 = _build_runtime_schema()["features"]

    def _mk_row(fid, rds):
        # Build the minimal subset of fields the ranking helper needs.
        return {
            "feature_id": fid,
            "acfg_rds": rds,
            "abs_acfg_rds": abs(rds),
            "sign": "positive" if rds > 0 else "negative" if rds < 0 else "zero",
        }

    print("[self-test] abs-ranking: negative feature can outrank positive")
    stats_neg = [
        _mk_row("I00", 0.10),
        _mk_row("I01", -0.50),
    ]
    ranked_neg = rank_acfg_stats_by_abs(stats_neg, schema16)
    check("|-0.50| outranks |+0.10| -> I01 first",
          ranked_neg[0]["feature_id"] == "I01"
          and ranked_neg[1]["feature_id"] == "I00",
          f"got {[r['feature_id'] for r in ranked_neg]}")
    check("rank_by_abs_acfg_rds is 1-based and assigned",
          ranked_neg[0]["rank_by_abs_acfg_rds"] == 1
          and ranked_neg[1]["rank_by_abs_acfg_rds"] == 2,
          f"got {[r['rank_by_abs_acfg_rds'] for r in ranked_neg]}")

    print("[self-test] abs-ranking: top-k can include negative features")
    stats_topk_neg = [
        _mk_row("S00", -0.30),
        _mk_row("S01", 0.20),
        _mk_row("S02", -0.10),
        _mk_row("S03", 0.05),
    ]
    ranked_topk = rank_acfg_stats_by_abs(stats_topk_neg, schema16)
    top2_ids = [row["feature_id"] for row in ranked_topk[:2]]
    check("top2 by |rds| == ['S00', 'S01'] (S00 is negative)",
          top2_ids == ["S00", "S01"], f"got {top2_ids}")

    print("[self-test] abs-ranking: zero feature falls last")
    stats_zero = [
        _mk_row("I00", 0.0),
        _mk_row("I01", 0.01),
        _mk_row("I02", -0.02),
    ]
    ranked_zero = rank_acfg_stats_by_abs(stats_zero, schema16)
    order_zero = [row["feature_id"] for row in ranked_zero]
    check("order is ['I02', 'I01', 'I00']",
          order_zero == ["I02", "I01", "I00"], f"got {order_zero}")
    check("zero-score feature has sign='zero'",
          ranked_zero[-1]["sign"] == "zero",
          f"got {ranked_zero[-1]['sign']}")

    print("[self-test] abs-ranking: deterministic schema-order tie-break")
    stats_tie = [
        # Reverse declaration order on purpose — schema order must still win.
        _mk_row("I01", -0.10),
        _mk_row("I00", 0.10),
    ]
    ranked_tie = rank_acfg_stats_by_abs(stats_tie, schema16)
    tie_order = [row["feature_id"] for row in ranked_tie]
    check("tie-break by schema order -> ['I00', 'I01']",
          tie_order == ["I00", "I01"], f"got {tie_order}")

    print("[self-test] abs-ranking: top4 mask follows abs ordering")
    # Synthetic top4 selection I01, S00, S03, S06 — verify the resulting
    # vec_mask reflects exactly those positions in schema order.
    expected_mask = "0100000010010010"
    mask_top4 = vec_mask_from_feature_ids(
        schema16, ["I01", "S00", "S03", "S06"],
    )
    check("top4 mask == 0100000010010010",
          mask_top4 == expected_mask,
          f"got {mask_top4}")

    print("[self-test] abs-ranking: no group quota, instructions can dominate")
    stats_no_quota = [
        _mk_row("I00", -0.90),
        _mk_row("I01", 0.80),
        _mk_row("I02", -0.70),
        _mk_row("I03", 0.60),
        _mk_row("S00", 0.10),
        _mk_row("S01", 0.09),
    ]
    ranked_nq = rank_acfg_stats_by_abs(stats_no_quota, schema16)
    top4_nq_ids = [row["feature_id"] for row in ranked_nq[:4]]
    check("top4 == ['I00','I01','I02','I03'] (no structural quota)",
          top4_nq_ids == ["I00", "I01", "I02", "I03"],
          f"got {top4_nq_ids}")

    # ------------------------------------------------------------------
    # Plan bofuzz_features_selection_ablation_plan.md — selection views.
    # ------------------------------------------------------------------
    def _mk_row_full(fid, rds, gini, mi=0.0):
        return {
            "feature_id": fid,
            "feature_name": fid,
            "group": "instruction" if fid.startswith("I") else "structural",
            "acfg_rds": rds,
            "abs_acfg_rds": abs(rds),
            "sign": "positive" if rds > 0 else "negative" if rds < 0 else "zero",
            "gini_strength": gini,
            "moran_i_rank_strength": mi,
        }

    print("[self-test] stable_target_seed: deterministic and varies by inputs")
    s1 = stable_target_seed("foo", 0xFA1C4)
    s2 = stable_target_seed("foo", 0xFA1C4)
    s3 = stable_target_seed("bar", 0xFA1C4)
    s4 = stable_target_seed("foo", 0xFA1C5)
    check("same target+seed -> same derived seed", s1 == s2, f"got {s1} vs {s2}")
    check("different target -> different derived seed",
          s1 != s3, f"got {s1} vs {s3}")
    check("different base seed -> different derived seed",
          s1 != s4, f"got {s1} vs {s4}")
    check("derived seed fits in 64-bit unsigned",
          0 <= s1 < (1 << 64), f"got {s1}")

    print("[self-test] rank_by_gini: descending with schema tie-break")
    gini_rows = [
        _mk_row_full("I00", 0.0, 0.20),
        _mk_row_full("I01", 0.0, 0.50),
        _mk_row_full("I02", 0.0, 0.50),  # ties I01 by gini, but later in schema
        _mk_row_full("S00", 0.0, 0.10),
    ]
    ranked_g = rank_acfg_stats_by_gini(gini_rows, schema16)
    order_g = [row["feature_id"] for row in ranked_g]
    check("gini ranking order is ['I01','I02','I00','S00']",
          order_g == ["I01", "I02", "I00", "S00"], f"got {order_g}")
    check("rank_by_gini is 1-based and assigned",
          [r["rank_by_gini"] for r in ranked_g] == [1, 2, 3, 4],
          f"got {[r['rank_by_gini'] for r in ranked_g]}")

    print("[self-test] select_random6_features: deterministic across runs")
    ids_a, derived_a = select_random6_features(schema16, "tgt", 0xFA1C4)
    ids_b, derived_b = select_random6_features(schema16, "tgt", 0xFA1C4)
    check("random6 same target+seed -> same id sequence",
          ids_a == ids_b, f"got {ids_a} vs {ids_b}")
    check("random6 same target+seed -> same derived seed",
          derived_a == derived_b, f"got {derived_a} vs {derived_b}")
    check("random6 returns exactly six features",
          len(ids_a) == 6, f"got {len(ids_a)}")
    check("random6 features are unique",
          len(set(ids_a)) == 6, f"got {ids_a}")
    valid_ids = {spec["id"] for spec in schema16}
    check("random6 features are valid schema IDs",
          set(ids_a).issubset(valid_ids), f"got {ids_a}")

    print("[self-test] random6 varies with target name and seed")
    ids_c, _ = select_random6_features(schema16, "other", 0xFA1C4)
    ids_d, _ = select_random6_features(schema16, "tgt", 0xFA1C5)
    # Different targets / seeds are not guaranteed to produce a different
    # 6-of-16 multiset (collisions are possible) but in practice these
    # specific inputs do differ; the strong contract is just that the
    # derived seed is different.
    check("random6 different target derives different seed",
          stable_target_seed("tgt", 0xFA1C4)
          != stable_target_seed("other", 0xFA1C4),
          "derived seeds collided")
    check("random6 different base seed derives different seed",
          stable_target_seed("tgt", 0xFA1C4)
          != stable_target_seed("tgt", 0xFA1C5),
          "derived seeds collided")

    print("[self-test] make_feature_selection_payload: structure + vec_mask")
    payload_rows = [
        _mk_row_full("S02", 0.30, 0.40),
        _mk_row_full("I00", -0.20, 0.10),
    ]
    # Annotate ranks on each row so feature_details has them.
    rank_acfg_stats_by_abs(payload_rows, schema16)
    rank_acfg_stats_by_gini(payload_rows, schema16)
    pl = make_feature_selection_payload("test rule", payload_rows, schema16)
    check("payload features preserve input order",
          pl["features"] == ["S02", "I00"], f"got {pl['features']}")
    expected_pl_mask = vec_mask_from_feature_ids(schema16, ["S02", "I00"])
    check("payload vec_mask matches schema-order recomputation",
          pl["vec_mask"] == expected_pl_mask,
          f"got {pl['vec_mask']} expected {expected_pl_mask}")
    check("payload feature_details has all required fields",
          all(
              {"feature_id", "feature_name", "group", "acfg_rds",
               "abs_acfg_rds", "sign", "rank_by_abs_acfg_rds",
               "gini_strength", "rank_by_gini",
               "moran_i_rank_strength"}.issubset(fd.keys())
              for fd in pl["feature_details"]
          ), f"got {pl['feature_details']}")

    print("[self-test] save_acfg_statistics_json: full selection-view contract")
    # Synthesize a tiny but full schema and ranked stats so we can exercise
    # save_acfg_statistics_json end-to-end without an IDA dependency.
    import tempfile
    synth_rows = []
    schema_ids = [spec["id"] for spec in schema16]
    # Give each feature a unique rds and gini so ranks are total orders.
    for i, fid in enumerate(schema_ids):
        # I03 deliberately gets a high gini but moderate rds so the top6
        # views diverge (covers Decision 4 + overlap metadata).
        if fid == "I03":
            rds, gini = 0.05, 0.95
        else:
            rds = 0.5 - i * 0.01
            gini = 0.30 + (i * 0.001)
        synth_rows.append(_mk_row_full(fid, rds, gini, mi=rds / 2.0))

    ranked_synth = rank_acfg_stats_by_abs(synth_rows, schema16)
    rank_acfg_stats_by_gini(synth_rows, schema16)
    with tempfile.TemporaryDirectory() as tmp:
        result = save_acfg_statistics_json(
            tmp, "synthetic", "synthetic_target", schema16,
            ranked_synth, n_nodes=42, n_edges=87,
            signal_source="norm", edge_mode="directed", eps=1e-8,
            runtime_map_meta={"mode": "sum"},
            random_feature_seed=0xFA1C4,
        )
        with open(result["stats_path"]) as fh:
            stats_obj = json.load(fh)

        check("no generic top6 field emitted",
              "top6" not in stats_obj, f"keys={sorted(stats_obj.keys())}")
        for key in ("top6_abs_acfg_rds", "top6_gini", "random6",
                    "selection_views", "selection_view_overlap"):
            check(f"statistics JSON has {key!r}",
                  key in stats_obj, f"keys={sorted(stats_obj.keys())}")

        # Decision 5 + Step 5: top6_abs_acfg_rds matches first 6 of abs ranking.
        expected_abs_ids = [row["feature_id"] for row in ranked_synth[:6]]
        check("top6_abs_acfg_rds.features == first six abs-ranked",
              stats_obj["top6_abs_acfg_rds"]["features"] == expected_abs_ids,
              f"got {stats_obj['top6_abs_acfg_rds']['features']}")

        # Decision 4 + Step 6: top6_gini matches first 6 by Gini-only ranking.
        gini_sorted = sorted(
            synth_rows,
            key=lambda r: (-r["gini_strength"],
                           build_schema_index(schema16).get(
                               r["feature_id"], 10**9)),
        )
        expected_gini_ids = [r["feature_id"] for r in gini_sorted[:6]]
        check("top6_gini.features == first six gini-ranked",
              stats_obj["top6_gini"]["features"] == expected_gini_ids,
              f"got {stats_obj['top6_gini']['features']}")
        # In this synthesis I03 has the largest gini so it MUST show up in
        # top6_gini but not necessarily in top6_abs_acfg_rds.
        check("synthetic I03 is in top6_gini",
              "I03" in stats_obj["top6_gini"]["features"],
              f"got {stats_obj['top6_gini']['features']}")

        # Decision 6/7: random6 metadata is deterministic.
        rnd = stats_obj["random6"]
        check("random6.random_feature_seed == '0xfa1c4'",
              rnd["random_feature_seed"] == "0xfa1c4",
              f"got {rnd.get('random_feature_seed')!r}")
        check("random6.random_feature_seed_int == int('0xfa1c4', 16)",
              rnd["random_feature_seed_int"] == int("0xfa1c4", 16),
              f"got {rnd.get('random_feature_seed_int')!r}")
        check("random6.derived_seed matches stable_target_seed",
              rnd["derived_seed"]
              == stable_target_seed("synthetic_target", 0xFA1C4),
              f"got {rnd.get('derived_seed')!r}")
        check("random6.features has six unique schema IDs",
              len(rnd["features"]) == 6 and len(set(rnd["features"])) == 6,
              f"got {rnd['features']}")

        # vec_mask recomputes for every view (plan test 6).
        for view in ("top6_abs_acfg_rds", "top6_gini", "random6"):
            recomputed = vec_mask_from_feature_ids(
                schema16, stats_obj[view]["features"],
            )
            check(f"{view}.vec_mask recomputes from schema order",
                  stats_obj[view]["vec_mask"] == recomputed,
                  f"got {stats_obj[view]['vec_mask']} expected {recomputed}")

        # selection_views metadata is exactly as locked in by decision 10.
        sv = stats_obj["selection_views"]
        check("selection_views.available is the locked triple",
              sv["available"]
              == ["top6_abs_acfg_rds", "top6_gini", "random6"],
              f"got {sv.get('available')}")
        check("selection_views.runtime_default is null",
              sv["runtime_default"] is None,
              f"got {sv.get('runtime_default')!r}")

        # selection_view_overlap is a non-negative int trio.
        ov = stats_obj["selection_view_overlap"]
        for k in ("top6_abs_vs_gini", "top6_abs_vs_random6",
                  "top6_gini_vs_random6"):
            check(f"selection_view_overlap.{k} is in [0, 6]",
                  isinstance(ov.get(k), int) and 0 <= ov[k] <= 6,
                  f"got {ov.get(k)!r}")

        # Standalone mask files match the JSON (plan decision 8 / step 12).
        for view, path_key in (
            ("top6_abs_acfg_rds", "top6_abs_acfg_rds_mask_path"),
            ("top6_gini",         "top6_gini_mask_path"),
            ("random6",           "random6_mask_path"),
        ):
            with open(result[path_key]) as fh:
                disk_mask = fh.read().strip()
            check(f"{view} standalone mask file matches JSON vec_mask",
                  disk_mask == stats_obj[view]["vec_mask"],
                  f"file={disk_mask} json={stats_obj[view]['vec_mask']}")

    if failures:
        print(f"\n[self-test] FAILED ({len(failures)} failures)")
        for f in failures:
            print(f"    - {f}")
        raise AssertionError(
            f"{len(failures)} ACFG self-test(s) failed: {failures}"
        )
    print("\n[self-test] ALL CHECKS PASSED")
    return 0


def save_acfg_feature_ranking_debug(out_dir, base, ranked_stats):
    """Optional human-readable per-feature ranking dump.

    Rows are emitted in abs-ranking order, so the file is safe to consume
    as the canonical ranking text export. Both the abs-RDS rank
    (``rank_abs``) and the Gini-only rank (``rank_gini``) are included so
    the file is also useful when inspecting Gini-only ablation runs.
    """
    out_path = os.path.join(out_dir, f"{base}_acfg_feature_ranking.txt")
    header_fmt = (
        "{:<9s} {:<10s} {:<11s} {:<28s} "
        "{:>14s} {:>14s} {:>8s} {:>14s} {:>14s} {:>5s}\n"
    )
    row_fmt = (
        "{:<9d} {:<10d} {:<11s} {:<28s} "
        "{:>+14.6f} {:>14.6f} {:>8s} {:>14.6f} {:>+14.6f} {:>5d}\n"
    )
    with open(out_path, "w") as f:
        f.write(
            header_fmt.format(
                "rank_abs", "rank_gini", "feature_id", "feature_name",
                "acfg_rds", "abs_acfg_rds", "sign",
                "gini", "moran_i", "act",
            )
        )
        f.write("-" * 142 + "\n")
        for row in ranked_stats:
            f.write(
                row_fmt.format(
                    row["rank_by_abs_acfg_rds"],
                    row.get("rank_by_gini", 0),
                    row["feature_id"],
                    row["feature_name"],
                    row["acfg_rds"],
                    row["abs_acfg_rds"],
                    row["sign"],
                    row["gini_strength"],
                    row["moran_i_rank_strength"],
                    row["active_count"],
                )
            )
    if VERBOSE:
        print(f"[+] Saved ACFG feature ranking debug -> {out_path}")
    return out_path


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
            if nv < 0.0:
                errors.append(f"BB {hex(bb_ea)}: norm {name} is negative: {nv}")
            if nv > 1.0 + NORMALIZATION_EPS:
                errors.append(f"BB {hex(bb_ea)}: norm {name} exceeds [0,1]: {nv}")
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

        for i, x in enumerate(arr):
            fv = float(x)
            if not math.isfinite(fv):
                raise RuntimeError(f"non-finite runtime feature: {name}[{i}]={x}")
            if fv < 0.0:
                raise RuntimeError(
                    f"negative runtime feature forbidden under simplex mode: {name}[{i}]={x}"
                )
            if fv > 1.0 + NORMALIZATION_EPS:
                raise RuntimeError(f"runtime feature exceeds [0,1]: {name}[{i}]={x}")

# ======================= EXPORT =======================
def _cross_platform_basename(path):
    """Return the basename of ``path`` treating both '/' and '\\\\' as separators.

    Needed because ``ida_nalt.get_input_file_path()`` can return Windows-style
    paths when the IDB was originally created on Windows.
    """
    if not path:
        return path
    return os.path.basename(path.replace("\\", "/"))


# NOTE: the historical per-PC ``build_and_save_features_map`` and
# ``build_and_save_features_map_for_u`` helpers used a per-block direct lookup
# (with ``EPS_NON_TARGET`` for non-target PCs). They have been replaced by the
# ACFG Voronoi region aggregation pipeline (plan Decision 9). The current
# default map and debug JSON are emitted inline from ``run_extraction`` using
# ``build_voronoi_runtime_feature_arrays`` so that every sancov site reflects
# the directed-successor Voronoi region it represents, not just its seed
# block.

def _build_runtime_schema():
    """Build the canonical runtime features_schema.json content (schema v3)."""
    feature_ids = [
        "I00", "I01", "I02", "I03", "I04", "I05", "I06", "I07",
        "S00", "S01", "S02", "S03", "S04", "S05", "S06", "S07",
    ]
    features = []
    for fid, name in zip(feature_ids, ATTR_NAMES):
        group = "instruction" if fid.startswith("I") else "structural"
        entry = {"id": fid, "name": name, "group": group}
        if name == "centrality":
            entry["aliases"] = ["betweenness"]
        features.append(entry)
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "features": features,
    }


def save_runtime_schema(out_dir):
    """Write the canonical BOFuzz/static_analysis/features_schema.json."""
    schema = _build_runtime_schema()
    schema_path = os.path.join(out_dir, "features_schema.json")
    with open(schema_path, "w") as f:
        json.dump(schema, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved runtime features_schema.json -> {schema_path}")
    return schema_path


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
        "normalization": normalization_metadata(),
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
            "If --input-file points to a .i64 database, output basename may include the .i64 suffix",
        ],
    }
    if execution is not None:
        schema["execution"] = execution
    schema_path = os.path.join(out_dir, f"{base}_features_schema.json")
    with open(schema_path, "w") as f:
        json.dump(schema, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved target schema JSON -> {schema_path}")
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

    # ---- ACFG statistics flags (Decision 8 / 4 / 5 / 2) ----
    parser.add_argument(
        "--no-acfg-stats",
        action="store_true",
        help="Disable ACFG-RDS statistics export.",
    )
    parser.add_argument(
        "--acfg-stats-eps",
        type=float,
        default=1e-8,
        help="Near-zero threshold for ACFG-RDS feature strength.",
    )
    parser.add_argument(
        "--acfg-stats-signal",
        choices=["norm", "raw"],
        default="norm",
        help="Feature signal source for ACFG statistics. Default: norm.",
    )
    parser.add_argument(
        "--acfg-edge-mode",
        choices=["directed", "undirected"],
        default="directed",
        help="CFG adjacency mode for Moran's I. Default: directed.",
    )
    parser.add_argument(
        "--random-feature-seed",
        type=lambda s: int(s, 0),
        default=0xFA1C4,
        help=(
            "Base seed for the deterministic random6 feature baseline. "
            "Accepts decimal (e.g. 1024452) or 0x-prefixed hex (e.g. 0xfa1c4)."
        ),
    )

    # ---- Sancov-site Voronoi aggregation flags (Decision 9 / 3 / 10) ----
    parser.add_argument(
        "--sancov-agg-mode",
        choices=["none", "sum"],
        default="sum",
        help="Aggregation mode for sancov-aligned runtime feature maps. Default: sum.",
    )
    parser.add_argument(
        "--sancov-voronoi-distance",
        choices=["directed-successor"],
        default="directed-successor",
        help=(
            "Graph distance mode for assigning ACFG blocks to sancov Voronoi "
            "regions. Default: directed-successor."
        ),
    )
    parser.add_argument(
        "--sancov-voronoi-gamma",
        type=float,
        default=0.5,
        help="Distance decay factor for Voronoi weighted aggregation.",
    )

    # ---- Pure-Python self-test (Plan section 17) ----
    parser.add_argument(
        "--self-test-acfg-stats",
        action="store_true",
        help=(
            "Run pure-Python ACFG statistics and Voronoi aggregation "
            "self-tests and exit."
        ),
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

    # =====================================================================
    # ACFG construction + Voronoi partition over directed-successor edges
    # =====================================================================
    print("[+] Building ACFG (full target-only) ...")
    node_order, node_index = build_acfg_index(blocks)
    n_nodes = len(node_order)
    acfg_adj = build_acfg_adjacency(CFG, node_index, args.acfg_edge_mode)
    n_edges = sum(len(vs) for vs in acfg_adj.values())
    voronoi_adj = build_voronoi_adjacency(CFG, node_index)
    print(f"    ACFG nodes={n_nodes} edges_{args.acfg_edge_mode}={n_edges}")

    print("[+] Mapping sancov sites to ACFG seed nodes ...")
    bb_cache = BBCache()
    sancov_seeds = build_sancov_seed_nodes(pcs, bb_cache, blocks, node_index)
    # Fail fast if any two sancov sites map to the same ACFG block.
    validate_unique_sancov_seed_nodes(sancov_seeds)

    print(
        f"[+] Building ACFG Voronoi regions "
        f"(distance={args.sancov_voronoi_distance}, gamma={args.sancov_voronoi_gamma}) ..."
    )
    regions_by_sancov, node_assignment, unassigned_nodes = build_acfg_voronoi_regions(
        n_nodes, sancov_seeds, voronoi_adj,
    )
    valid_seed_count = sum(
        1 for s in sancov_seeds if s.get("node_index") is not None
    )
    unmapped_seed_count = len(sancov_seeds) - valid_seed_count
    assigned_count = n_nodes - len(unassigned_nodes)
    print(
        f"    seeds total={len(sancov_seeds)} valid={valid_seed_count} "
        f"unmapped={unmapped_seed_count}; "
        f"assigned_nodes={assigned_count} unassigned_nodes={len(unassigned_nodes)}"
    )

    # =====================================================================
    # Voronoi-aggregated runtime feature arrays (sancov-aligned)
    # =====================================================================
    schema_features = _build_runtime_schema()["features"]
    if args.sancov_agg_mode == "sum":
        print("[+] Aggregating runtime features via Voronoi region sums ...")
        feature_arrays_by_name = build_voronoi_runtime_feature_arrays(
            blocks, node_order, schema_features, sancov_seeds,
            regions_by_sancov, node_assignment, args.sancov_voronoi_gamma,
            signal_source="norm",
        )
    else:
        # ``none`` mode keeps the legacy "direct seed value" semantics: each
        # sancov site emits its seed block's normalized feature value (or 0
        # when the PC is not in a target block). Kept for ablation only.
        print("[+] Sancov aggregation disabled (--sancov-agg-mode none) ...")
        feature_arrays_by_name = {spec["name"]: [] for spec in schema_features}
        for seed in sancov_seeds:
            node_i = seed.get("node_index")
            if node_i is None:
                vec = [0.0] * len(schema_features)
            else:
                ea = node_order[node_i]
                b = blocks[ea]
                vec = [finite_or_zero(b.norm_attrs.get(spec["name"], 0.0))
                       for spec in schema_features]
            for spec, v in zip(schema_features, vec):
                feature_arrays_by_name[spec["name"]].append(v)
        for spec in schema_features:
            name = spec["name"]
            feature_arrays_by_name[name] = _normalize_nonnegative_log1p_minmax_feature(
                name, feature_arrays_by_name[name],
            )

    # Keyed by ATTR_NAMES for backward-compat downstream consumers.
    attr_arrays = {name: feature_arrays_by_name[name] for name in ATTR_NAMES}
    validate_exported_maps(attr_arrays, pcs)

    # Save per-feature JSONs ``<base>_features_map_<name>.json``.
    for name in ATTR_NAMES:
        out_file = os.path.join(out_dir, f"{base}_features_map_{name}.json")
        with open(out_file, "w") as f:
            json.dump(attr_arrays[name], f, indent=2)
        if VERBOSE:
            print(f"[+] Saved features_map[{name}] -> {out_file}")

    # Merged 16-key map (Voronoi-aggregated, sancov-aligned).
    merged_path = os.path.join(out_dir, f"{base}_features_map.json")
    with open(merged_path, "w") as f:
        json.dump(attr_arrays, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved merged 16-key features_map -> {merged_path}")

    # =====================================================================
    # Default map (directional_weight per sancov site) + debug JSON
    # =====================================================================
    n_sancov = len(sancov_seeds)
    default_fmap = []
    dbg_entries = []
    for sancov_index in range(n_sancov):
        seed = sancov_seeds[sancov_index]
        vec_norm = [attr_arrays[name][sancov_index] for name in ATTR_NAMES]
        node_i = seed.get("node_index")
        region = regions_by_sancov.get(sancov_index, [])
        if node_i is None:
            weight = 0.0
            entry = {
                "index": sancov_index,
                "pc": seed.get("pc"),
                "bb_start": seed.get("bb_start"),
                "func": None,
                "attrs_norm_voronoi": dict(zip(ATTR_NAMES, vec_norm)),
                "voronoi_region_size": 0,
                "weight": weight,
                "note": seed.get("note", "unmapped"),
            }
        else:
            weight = max(0.0, finite_or_zero(directional_weight(vec_norm)))
            seed_ea = node_order[node_i]
            b = blocks[seed_ea]
            entry = {
                "index": sancov_index,
                "pc": seed.get("pc"),
                "bb_start": seed.get("bb_start"),
                "func": hex(b.func_ea),
                "seed_node_index": node_i,
                "attrs_raw_seed": {k: finite_or_zero(v) for k, v in b.raw_attrs.items()},
                "attrs_norm_voronoi": dict(zip(ATTR_NAMES, vec_norm)),
                "voronoi_region_size": len(region),
                "weight": weight,
            }
        if not math.isfinite(float(weight)) or weight < 0.0:
            raise RuntimeError(f"invalid default feature-map weight at {sancov_index}: {weight}")
        default_fmap.append(weight)
        dbg_entries.append(entry)

    default_path = os.path.join(out_dir, f"{base}_features_map_default.json")
    with open(default_path, "w") as f:
        json.dump(default_fmap, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved features_map_default -> {default_path}")

    dbg_path = os.path.join(out_dir, f"{base}_features_map.debug.json")
    dbg_payload = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "attr_names": ATTR_NAMES,
        "normalization": normalization_metadata(),
        "reachable_edges": reachable_edges,
        "runtime_map_aggregation": {
            "mode": args.sancov_agg_mode,
            "gamma": args.sancov_voronoi_gamma,
            "distance_mode": args.sancov_voronoi_distance,
            "valid_seed_nodes": valid_seed_count,
            "unmapped_sancov_sites": unmapped_seed_count,
            "assigned_nodes": assigned_count,
            "unassigned_nodes": len(unassigned_nodes),
        },
        "pcs": [hex(p) for p in pcs],
        "map": dbg_entries,
    }
    with open(dbg_path, "w") as f:
        json.dump(dbg_payload, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved debug map -> {dbg_path}")

    # =====================================================================
    # ACFG / Voronoi / Statistics exports
    # =====================================================================
    target_name = base

    acfg_path = save_acfg_json(
        out_dir, base, target_name, blocks, node_order, node_index,
        acfg_adj,
        signal_source=args.acfg_stats_signal,
        edge_mode=args.acfg_edge_mode,
        voronoi_distance=args.sancov_voronoi_distance,
        eps=args.acfg_stats_eps,
    )

    voronoi_path = save_acfg_voronoi_json(
        out_dir, base, target_name, sancov_seeds, regions_by_sancov,
        node_assignment, unassigned_nodes, n_nodes,
        gamma=args.sancov_voronoi_gamma,
        distance_mode=args.sancov_voronoi_distance,
        aggregation_mode=args.sancov_agg_mode,
    )

    sancov_acfg_path = save_sancov_acfg_json(
        out_dir, base, target_name, sancov_seeds, regions_by_sancov,
        node_assignment, acfg_adj,
    )

    stats_path = None
    top4_mask_path = None
    top6_abs_mask_path = None
    top6_gini_mask_path = None
    random6_mask_path = None
    if not args.no_acfg_stats:
        print("[+] Computing ACFG-RDS statistics over full target ACFG ...")
        stats_unranked, ranked_stats = compute_acfg_feature_statistics(
            blocks, schema_features, node_order, acfg_adj,
            signal_source=args.acfg_stats_signal,
            eps=args.acfg_stats_eps,
            edge_mode=args.acfg_edge_mode,
        )
        n_nodes_total = n_nodes
        unassigned_ratio = (
            len(unassigned_nodes) / float(n_nodes_total)
            if n_nodes_total > 0 else 0.0
        )
        runtime_map_meta = {
            "mode": args.sancov_agg_mode,
            "gamma": args.sancov_voronoi_gamma,
            "distance_mode": args.sancov_voronoi_distance,
            "seed_count": len(sancov_seeds),
            "valid_seed_nodes": valid_seed_count,
            "unmapped_sancov_sites": unmapped_seed_count,
            "assigned_nodes": assigned_count,
            "unassigned_nodes": len(unassigned_nodes),
            "unassigned_node_ratio": finite_or_zero(unassigned_ratio),
        }
        stats_result = save_acfg_statistics_json(
            out_dir, base, target_name, schema_features, ranked_stats,
            n_nodes, n_edges,
            signal_source=args.acfg_stats_signal,
            edge_mode=args.acfg_edge_mode,
            eps=args.acfg_stats_eps,
            runtime_map_meta=runtime_map_meta,
            random_feature_seed=args.random_feature_seed,
        )
        stats_path = stats_result["stats_path"]
        top4_mask_path = stats_result["top4_mask_path"]
        top6_abs_mask_path = stats_result["top6_abs_acfg_rds_mask_path"]
        top6_gini_mask_path = stats_result["top6_gini_mask_path"]
        random6_mask_path = stats_result["random6_mask_path"]
        if VERBOSE:
            save_acfg_feature_ranking_debug(out_dir, base, ranked_stats)
    else:
        print("[+] ACFG-RDS statistics disabled (--no-acfg-stats)")

    # =====================================================================
    # Legacy schema files (unchanged)
    # =====================================================================
    execution = _build_execution_metadata(args, bin_path, out_dir)
    execution["output_basename"] = base
    schema_path = save_schema_json(out_dir, base, execution=execution)
    runtime_schema_path = save_runtime_schema(out_dir)

    time_end = time.time()
    print(f"\n[+] DONE.")
    print(f"    Schema version : {FEATURE_SCHEMA_VERSION}")
    print(f"    Feature dims   : {len(ATTR_NAMES)}")
    print(f"    Blocks         : {len(blocks)}")
    print(f"    Merged map     : {merged_path}")
    print(f"    Default map    : {default_path}")
    print(f"    Debug          : {dbg_path}")
    print(f"    ACFG           : {acfg_path}")
    print(f"    ACFG Voronoi   : {voronoi_path}")
    print(f"    Sancov ACFG    : {sancov_acfg_path}")
    if stats_path:
        print(f"    Statistics            : {stats_path}")
        print(f"    Top4 mask             : {top4_mask_path}")
        print(f"    Top6 abs_acfg_rds mask: {top6_abs_mask_path}")
        print(f"    Top6 gini mask        : {top6_gini_mask_path}")
        print(f"    Random6 mask          : {random6_mask_path}")
        print(f"    Random6 base seed     : 0x{int(args.random_feature_seed):x}")
    print(f"    Schema         : {schema_path}")
    print(f"    Runtime schema : {runtime_schema_path}")
    print(f"    Sancov agg     : {args.sancov_agg_mode} gamma={args.sancov_voronoi_gamma}")
    print(f"    Moran edge     : {args.acfg_edge_mode}")
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

    # ``--self-test-acfg-stats`` runs entirely on Python stdlib and must
    # NOT touch IDA. Handle it before bootstrap.
    if getattr(args, "self_test_acfg_stats", False):
        return run_acfg_self_tests()

    bootstrap_ida_environment(args)

    try:
        return run_extraction(args)
    finally:
        cleanup_ida_environment()


if __name__ == "__main__":
    main()
