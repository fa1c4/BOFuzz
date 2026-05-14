# -*- coding: utf-8 -*-
"""
Build {binary}_features_map.json aligned to sancov pc-table,
USING ONLY the target-binary-exclusive CFG/CG (reachable from LLVMFuzzerTestOneInput).

Canonical 16-feature basic-block static extractor (schema v3).

No external deps. Designed for IDA Pro (tested on Python 3 IDAPython).
"""

import os, json, math, time, logging
from collections import defaultdict, deque

import idaapi
import idc
import ida_bytes
import ida_nalt
import ida_segment
import idautils

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

# ---- Const-data segments ----
CONST_DATA_SEGMENT_NAMES = {
    ".rodata",
    ".rdata",
    "__const",
    "__cstring",
    ".const",
    ".data.rel.ro",
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

# ======================= OPERAND / REFERENCE CLASSIFICATION =======================
def get_segment_name(ea):
    seg = idaapi.getseg(ea)
    if seg:
        return (idaapi.get_segm_name(seg) or "").strip()
    return ""

def is_text_addr(addr):
    name = get_segment_name(addr).lower()
    return name in ('.text', 'text', 'code', '__text')

def is_const_data_addr(addr):
    name = get_segment_name(addr)
    return name in CONST_DATA_SEGMENT_NAMES

def is_string_addr(addr, string_addrs):
    if addr in string_addrs:
        return True
    s = get_string_at_address(addr)
    return s is not None and len(s) >= 2

def classify_operand_value(value, string_addrs):
    """
    Return one of:
      "string_ref", "const_data_ref", "code_ref",
      "numeric_immediate", "unknown"
    """
    if value is None or value == 0:
        return "numeric_immediate"
    if value == idc.BADADDR:
        return "unknown"
    seg = idaapi.getseg(value)
    if seg is None:
        return "numeric_immediate"
    if is_string_addr(value, string_addrs):
        return "string_ref"
    if is_const_data_addr(value):
        return "const_data_ref"
    if is_text_addr(value):
        return "code_ref"
    return "numeric_immediate"

def is_trivial_immediate(v):
    if v in TRIVIAL_IMMEDIATE_VALUES:
        return True
    if -256 <= v < 0:
        return True
    return False

# ======================= INSTRUCTION CLASSIFIERS =======================
def is_cmp_inst(mnem):
    if mnem in {"cmp", "test"}:
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
    True if instruction has an explicit memory operand.
    lea and call are excluded. Counts at most once per instruction.
    """
    if mnem == "lea":
        return False
    if mnem in {"call", "callq"} or mnem.startswith("call"):
        return False
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
_REF_OPERAND_TYPES = {idaapi.o_imm, idaapi.o_mem, idaapi.o_displ, idaapi.o_near, idaapi.o_far}

def extract_instruction_features(ea, string_addrs):
    """
    Return dict with instruction-level feature increments for a single instruction.
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
                    res["string_literal_ref_count"] += 1.0
                elif cls == "const_data_ref":
                    res["const_data_ref_count"] += 1.0
                elif cls == "numeric_immediate":
                    if FILTER_TRIVIAL_IMMEDIATES and is_trivial_immediate(v):
                        pass
                    else:
                        res["numeric_immediate_count"] += 1.0
            else:
                if v is not None and v != 0 and v != idc.BADADDR:
                    if is_string_addr(v, string_addrs):
                        res["string_literal_ref_count"] += 1.0
                    elif is_const_data_addr(v):
                        res["const_data_ref_count"] += 1.0
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

def build_function_call_graph():
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
            if m == 'call':
                tgt = idc.get_operand_value(cur, 0)
                if tgt != idc.BADADDR:
                    tgt_fn = idaapi.get_func(tgt)
                    if tgt_fn and function_filter(tgt_fn.start_ea):
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

# ======================= STRUCTURAL FEATURES =======================

# ---- 8.1 CFG degree ----
def compute_cfg_degree_features(CFG, blocks):
    preds = defaultdict(int)
    for u, outs in CFG.items():
        for v in outs:
            if v in blocks:
                preds[v] += 1

    for bb_ea, b in blocks.items():
        b.set_raw_attr("cfg_out_degree", float(len(CFG.get(bb_ea, set()))))
        b.set_raw_attr("cfg_in_degree", float(preds.get(bb_ea, 0)))

# ---- 8.2 Static descendant / ancestor (SCC condensation) ----
def _tarjan_scc(adj, nodes):
    """Tarjan's SCC algorithm. Returns list of SCCs (each SCC is a frozenset of node ids)."""
    index_counter = [0]
    stack = []
    on_stack = set()
    index = {}
    lowlink = {}
    result = []

    def strongconnect(v):
        index[v] = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack.add(v)

        for w in adj.get(v, ()):
            if w not in nodes:
                continue
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], index[w])

        if lowlink[v] == index[v]:
            component = set()
            while True:
                w = stack.pop()
                on_stack.discard(w)
                component.add(w)
                if w == v:
                    break
            result.append(frozenset(component))

    for v in nodes:
        if v not in index:
            strongconnect(v)

    return result

def _compute_reachable_sizes_on_dag(dag, scc_sizes, scc_order):
    """Given a DAG (scc_id -> set of successor scc_ids) and sizes, compute total reachable node count from each SCC."""
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
        total += scc_sizes[scc_id] - 1  # same SCC minus self
        reachable[scc_id] = total
    return reachable

def compute_static_reachability_features(CFG, blocks):
    nodes = set(blocks.keys())
    if not nodes:
        return

    sccs = _tarjan_scc(CFG, nodes)

    node_to_scc = {}
    scc_sizes = {}
    for idx, scc in enumerate(sccs):
        scc_sizes[idx] = len(scc)
        for n in scc:
            node_to_scc[n] = idx

    # Build SCC DAG (forward)
    scc_dag_fwd = defaultdict(set)
    for u in nodes:
        u_scc = node_to_scc[u]
        for v in CFG.get(u, ()):
            if v in nodes:
                v_scc = node_to_scc[v]
                if u_scc != v_scc:
                    scc_dag_fwd[u_scc].add(v_scc)

    # Build SCC DAG (reverse)
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

# ---- 8.3 Entry depth ----
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

# ---- 8.4 Loop features (natural loop + SCC fallback) ----
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

        # Find entry BB
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
        natural_loops = []
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
            natural_loops.append((header, latch, frozenset(loop_nodes)))

        # Accumulate nesting depth
        for header, latch, loop_nodes in natural_loops:
            for n in loop_nodes:
                loop_nesting[n] += 1

            loop_boundary[header] = 1.0
            if "header" not in loop_roles_debug[header]:
                loop_roles_debug[header].append("header")

            loop_boundary[latch] = 1.0
            if "latch" not in loop_roles_debug[latch]:
                loop_roles_debug[latch].append("latch")

            # Loop exit: edges from loop to non-loop
            for n in loop_nodes:
                for s in func_succs.get(n, ()):
                    if s not in loop_nodes:
                        loop_boundary[n] = 1.0
                        if "exit_source" not in loop_roles_debug[n]:
                            loop_roles_debug[n].append("exit_source")
                        loop_boundary[s] = 1.0
                        if "exit_target" not in loop_roles_debug[s]:
                            loop_roles_debug[s].append("exit_target")

        # SCC fallback: if function-local SCC has size > 1 or self-loop, treat as loop
        func_sccs = _tarjan_scc(func_succs, func_bbs)
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
                if loop_nesting[n] == 0:
                    loop_nesting[n] = max(loop_nesting[n], 1)
                for s in func_succs.get(n, ()):
                    if s not in scc:
                        loop_boundary[n] = 1.0
                        loop_boundary[s] = 1.0
                for p in func_preds.get(n, ()):
                    if p not in scc:
                        loop_boundary[n] = 1.0
                        loop_boundary[p] = 1.0

    for bb_ea, b in blocks.items():
        b.set_raw_attr("loop_nesting_depth", float(loop_nesting.get(bb_ea, 0)))
        b.set_raw_attr("loop_boundary_flag", float(loop_boundary.get(bb_ea, 0.0)))
        if bb_ea in loop_roles_debug:
            b.debug["loop_roles"] = loop_roles_debug[bb_ea]

# ---- 8.5 Centrality (betweenness, Brandes) ----
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

    norm = (len(sample_nodes) - 1) * (N - 1) if N > 1 else 1.0
    if norm <= 0:
        norm = 1.0
    for bb_ea in nodes:
        blocks[bb_ea].set_raw_attr("centrality", float(btw_acc.get(bb_ea, 0.0) / norm))

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

    for bb_ea, b in blocks.items():
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
        expected_out = float(len(CFG.get(bb_ea, set())))
        if b.get_raw_attr("cfg_out_degree") != expected_out:
            errors.append(f"BB {hex(bb_ea)}: cfg_out_degree mismatch")

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

# ======================= EXPORT =======================
def build_and_save_features_map(pcs, CFG, blocks, func_of_bb, reachable_edges=None):
    bin_path = ida_nalt.get_input_file_path()
    base = os.path.basename(bin_path)
    out_dir = os.path.dirname(bin_path) or os.getcwd()

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
                "weight": float(EPS_NON_TARGET),
                "note": "no_bb"
            })
            continue

        start = bb.start_ea
        if start in target_bb_set:
            b = blocks[start]
            w = directional_weight(b.to_attr_list_norm())
            if w == 0.0:
                w = EPS_NON_TARGET
            fmap.append(float(w))
            dbg.append({
                "index": idx,
                "pc": hex(pc),
                "bb_start": hex(start),
                "func": hex(b.func_ea),
                "attrs_raw": dict(b.raw_attrs),
                "attrs_norm": dict(b.norm_attrs),
                "weight": float(w)
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
                "weight": float(EPS_NON_TARGET),
                "note": "non_target"
            })

    # Default weight map
    out_path = os.path.join(out_dir, f"{base}_features_map_default.json")
    with open(out_path, "w") as f:
        json.dump(fmap, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved features_map_default -> {out_path}")

    # Debug JSON
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

def build_and_save_features_map_for_u(pcs, blocks, func_of_bb, u, out_filename):
    bin_path = ida_nalt.get_input_file_path()
    out_dir = os.path.dirname(bin_path) or os.getcwd()

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
            if w == 0.0:
                w = EPS_NON_TARGET
            fmap.append(float(w))
        else:
            fmap.append(float(EPS_NON_TARGET))

    out_path = os.path.join(out_dir, out_filename)
    with open(out_path, "w") as f:
        json.dump(fmap, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved features_map (u provided) -> {out_path}")
    return fmap, out_path

def save_schema_json(out_dir, base):
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
        "notes": [
            "cmp_inst_count is separate from arith_bitwise_count",
            "mem_inst_count counts explicit memory-access instructions only",
            "calls are counted in call_count only",
            "APageRank disabled by default",
        ],
    }
    schema_path = os.path.join(out_dir, f"{base}_features_schema.json")
    with open(schema_path, "w") as f:
        json.dump(schema, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved schema JSON -> {schema_path}")
    return schema_path

# ============================== MAIN ==============================
def main():
    time_start = time.time()
    bin_path = ida_nalt.get_input_file_path()
    print(f"[+] Binary: {bin_path}")
    print(f"[+] Feature schema version: {FEATURE_SCHEMA_VERSION}, dims: {len(ATTR_NAMES)}")

    # 1. Collect pcs
    pcs = collect_pcs_aligned_with_counters()
    print(f"[+] PCs collected (aligned with counters): {len(pcs)}")

    # 2. Resolve seed entries
    seeds = resolve_seed_entries(pcs)
    seed_names = [idc.get_func_name(ea) or hex(ea) for ea in seeds]
    print(f"[+] Seed entries: {seed_names}")

    # 3. Build function call graph
    call_g = build_function_call_graph()

    # 4. Target-only function reachability
    target_funcs = reachable_from_seeds(call_g, seeds)
    print(f"[+] Target-only function count: {len(target_funcs)}")

    # 5. Build target-only CFG and instruction-level features
    CFG, blocks, func_of_bb = build_target_cfg_and_features(target_funcs)
    print(f"[+] Target-only CFG: {len(blocks)} basic blocks, {sum(len(v) for v in CFG.values())} edges")

    if len(blocks) == 0:
        raise RuntimeError("Target-only CFG is empty. Check entry points/reachability or build symbols.")

    # 6. Structural features
    print("[+] Computing CFG degree features ...")
    compute_cfg_degree_features(CFG, blocks)

    print("[+] Computing static reachability (descendant/ancestor via SCC) ...")
    compute_static_reachability_features(CFG, blocks)

    print("[+] Computing depth (from entry function) ...")
    compute_depth_attribute(CFG, blocks, func_of_bb, call_g, seeds)

    print("[+] Computing loop features (natural loop + SCC fallback) ...")
    compute_loop_features(CFG, blocks, func_of_bb)

    print("[+] Computing centrality (betweenness) ...")
    compute_centrality_feature(CFG, blocks)

    # 7. Feature mode
    feature = 'both'
    apply_feature_mode(blocks, feature=feature)
    print(f"[+] Feature mode: {feature}")

    # 8. Normalize
    normalize_blocks(blocks)

    # 9. APageRank (disabled by default)
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

    # 10. Reachable edge stats
    reachable_edges = count_reachable_edges(CFG, func_of_bb, target_funcs)
    if VERBOSE:
        print(f"[+] Reachable edges from entries: {reachable_edges}")

    # 10.5. Validate
    validate_features(pcs, CFG, blocks)

    # 11. Export canonical feature maps, default map, debug, schema
    base = os.path.basename(bin_path)
    out_dir = os.path.dirname(bin_path) or os.getcwd()

    # Per-feature one-hot maps
    attr_arrays = {}
    dim = len(ATTR_NAMES)
    for i, name in enumerate(ATTR_NAMES):
        u_one_hot = [0.0] * dim
        u_one_hot[i] = 1.0
        out_file = f"{base}_features_map_{name}.json"
        fmap, _ = build_and_save_features_map_for_u(pcs, blocks, func_of_bb, u_one_hot, out_file)
        attr_arrays[name] = fmap

    # Merged 16-key dict map
    merged_path = os.path.join(out_dir, f"{base}_features_map.json")
    with open(merged_path, "w") as f:
        json.dump(attr_arrays, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved merged 16-key features_map -> {merged_path}")

    # Default weight map + debug JSON
    out_map, out_dbg = build_and_save_features_map(pcs, CFG, blocks, func_of_bb, reachable_edges)

    # Schema JSON
    schema_path = save_schema_json(out_dir, base)

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
    print(f"    Time           : {(time_end - time_start):.2f}s")


if __name__ == "__main__":
    main()
