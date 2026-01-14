# -*- coding: utf-8 -*-
"""
Build {binary}_features_map.json aligned to sancov pc-table,
USING ONLY the target-binary-exclusive CFG/CG (reachable from LLVMFuzzerTestOneInput).

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

# ----------------------------- CONFIG -----------------------------
SEED_ENTRY_NAMES = [
    "LLVMFuzzerTestOneInput",  # libFuzzer-style target entry
]
MAX_BETWEENNESS_SAMPLE = 10000     # Betweenness sampling cap (sample when the graph is large)
EPS_NON_TARGET = 1e-9              # Weight for non-target-domain PCs (keeps indices aligned; near-zero impact)
VERBOSE = True

log = logging.getLogger("target_features_map")
if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# set ATTRIBUTES NAMES
ATTR_NAMES = ["imme", "strc", "mem", "arith", "indeg", "offsp", "btw", "depth"]

# ---------------------- APAGERANK CONFIG ----------------------
USE_APAGERANK = True  
APAGERANK_DAMPING = 0.85   
APAGERANK_GAMMA = 1.0   
APAGERANK_TAU = 1.0     
APAGERANK_EPSILON = 0.01     
APAGERANK_ITER_MAX = 5       

# ------------------------ CORE UTILITIES (SELF-CONTAINED) ------------------------
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
    # Handle common prefixes
    for p in ('rep ', 'repe ', 'repz ', 'repne ', 'repnz ', 'lock '):
        if m.startswith(p):
            return m[len(p):]
    return m

# ---- STRING TABLE ----
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
        if not data: return None
        p = data.find(b'\x00')
        if p > 0:
            try:
                return data[:p].decode('utf-8', errors='ignore')
            except Exception:
                try:
                    return data[:p].decode('ascii', errors='ignore')
                except Exception:
                    pass
        # Rough attempt for UTF-16
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

# ---- INSTRUCTION CLASSIFICATION ----
_DIRECT_MEM = {
    'movsx','movzx','movsxd','movbe','lea',
    'push','pop','pusha','popa','pushad','popad','pushf','popf','pushfd','popfd','enter','leave',
    'movs','movsb','movsw','movsd','movsq','stos','stosb','stosw','stosd','stosq',
    'lods','lodsb','lodsw','lodsd','lodsq','scas','scasb','scasw','scasd','scasq',
    'cmps','cmpsb','cmpsw','cmpsd','cmpsq',
    'cmpxchg','cmpxchg8b','cmpxchg16b','xchg','xadd','bound','xlat',
    'lds','les','lfs','lgs','lss',
    'fld','fst','fstp','fild','fist','fistp','fbld','fbstp',
    'movss','movsd','movps','movpd','movaps','movapd','movups','movupd','movhps','movhpd','movlps','movlpd',
    'movdqa','movdqu','movq','movd',
}

def is_memory_operation(addr, mnem):
    try:
        if mnem in _DIRECT_MEM:
            return True
        for i in range(8):
            t = idc.get_operand_type(addr, i)
            if t == idaapi.o_void:
                break
            if t in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase):
                return True
            op = (idc.print_operand(addr, i) or '').lower()
            if '[' in op and ']' in op:
                return True
            if any(seg + ':' in op for seg in ('ds','es','ss','cs','fs','gs')):
                return True
        # Calls to common memory-related APIs also count
        if mnem == 'call':
            op0 = idc.print_operand(addr,0) or ''
            call_ea = idc.get_operand_value(addr,0)
            fn = idc.get_func_name(call_ea) if call_ea != idc.BADADDR else op0
            if fn:
                low = fn.lower()
                for k in ('malloc','calloc','realloc','alloca','free',
                          'memcpy','memcmp','memset','memmove','memchr',
                          'strcpy','strncpy','strcat','strncat','strlen','strcmp','strncmp',
                          'read','write','fopen','fread','fwrite','fclose','fgets','fputs','fgetc','fputc'):
                    if k in low:
                        return True
        return False
    except Exception:
        return False

def is_arithmetic_operation(addr, mnem):
    try:
        basic = {'add','adc','sub','sbb','mul','imul','div','idiv','inc','dec','neg','abs'}
        cmpops = {'cmp','test','cmpxchg','cmpxchg8b','cmpxchg16b'}
        bitlog = {'and','or','xor','not','bt','btc','btr','bts','bsf','bsr','popcnt','lzcnt','tzcnt','andn'}
        shift  = {'shl','shr','sal','sar','rol','ror','rcl','rcr','shld','shrd','shrx','shlx','sarx'}
        x87 = {'fadd','faddp','fiadd','fsub','fsubp','fisub','fsubr','fsubrp','fisubr','fmul','fmulp','fimul',
               'fdiv','fdivp','fidiv','fdivr','fdivrp','fidivr','fabs','fchs','fsqrt','fsin','fcos','fsincos',
               'fptan','fpatan','f2xm1','fyl2x','fyl2xp1','fscale','frndint','fxtract','fprem','fprem1',
               'fcom','fcomp','fcompp','ficom','ficomp','ftst','fxam'}
        sse_s = {'addss','addsd','subss','subsd','mulss','mulsd','divss','divsd','sqrtss','sqrtsd','rsqrtss','rcpss',
                 'minss','minsd','maxss','maxsd','comiss','comisd','ucomiss','ucomisd'}
        sse_p = {'addps','addpd','subps','subpd','mulps','mulpd','divps','divpd','sqrtps','sqrtpd','rsqrtps','rcpps',
                 'minps','minpd','maxps','maxpd','cmpps','cmppd','dpps','dppd'}
        sse_i = {'paddb','paddw','paddd','paddq','paddsb','paddsw','paddusb','paddusw',
                 'psubb','psubw','psubd','psubq','psubsb','psubsw','psubusb','psubusw',
                 'pmullw','pmulhw','pmulhuw','pmulld','pmuludq','pmuldq',
                 'pcmpeqb','pcmpeqw','pcmpeqd','pcmpeqq','pcmpgtb','pcmpgtw','pcmpgtd','pcmpgtq',
                 'pmaxsb','pmaxsw','pmaxsd','pmaxub','pmaxuw','pmaxud','pminsb','pminsw','pminsd','pminub','pminuw','pminud',
                 'pabsb','pabsw','pabsd','psadbw','pavgb','pavgw'}
        avx = {'vaddss','vaddsd','vaddps','vaddpd','vsubss','vsubsd','vsubps','vsubpd',
               'vmulss','vmulsd','vmulps','vmulpd','vdivss','vdivsd','vdivps','vdivpd',
               'vsqrtss','vsqrtsd','vsqrtps','vsqrtpd','vrsqrtss','vrsqrtps','vrcpss','vrcpps',
               'vminss','vminsd','vminps','vminpd','vmaxss','vmaxsd','vmaxps','vmaxpd',
               'vcmpss','vcmpsd','vcmppd','vcmpps',
               'vpaddb','vpaddw','vpaddd','vpaddq','vpaddsb','vpaddsw','vpaddusb','vpaddusw',
               'vpsubb','vpsubw','vpsubd','vpsubq','vpsubsb','vpsubsw','vpsubusb','vpsubusw',
               'vpmullw','vpmulhw','vpmulhuw','vpmulld','vpmuludq','vpmuldq',
               'vpcmpeqb','vpcmpeqw','vpcmpeqd','vpcmpeqq','vpcmpgtb','vpcmpgtw','vpcmpgtd','vpcmpgtq'}
        fma = {'vfmadd132ps','vfmadd132pd','vfmadd132ss','vfmadd132sd',
               'vfmadd213ps','vfmadd213pd','vfmadd213ss','vfmadd213sd',
               'vfmadd231ps','vfmadd231pd','vfmadd231ss','vfmadd231sd',
               'vfmsub132ps','vfmsub132pd','vfmsub132ss','vfmsub132sd',
               'vfmsub213ps','vfmsub213pd','vfmsub213ss','vfmsub213sd',
               'vfmsub231ps','vfmsub231pd','vfmsub231ss','vfmsub231sd',
               'vfnmadd132ps','vfnmadd132pd','vfnmadd132ss','vfnmadd132sd',
               'vfnmadd213ps','vfnmadd213pd','vfnmadd213ss','vfnmadd213sd',
               'vfnmadd231ps','vfnmadd231pd','vfnmadd231ss','vfnmadd231sd',
               'vfnmsub132ps','vfnmsub132pd','vfnmsub132ss','vfnmsub132sd',
               'vfnmsub213ps','vfnmsub213pd','vfnmsub213ss','vfnmsub213sd',
               'vfnmsub231ps','vfnmsub231pd','vfnmsub231ss','vfnmsub231sd'}
        cmov = {'cmovo','cmovno','cmovb','cmovc','cmovnae','cmovnb','cmovnc','cmovae',
                'cmove','cmovz','cmovne','cmovnz','cmovbe','cmovna','cmova','cmovnbe',
                'cmovs','cmovns','cmovp','cmovpe','cmovnp','cmovpo',
                'cmovl','cmovnge','cmovge','cmovnl','cmovle','cmovng','cmovg','cmovnle'}
        if mnem in (basic | cmpops | bitlog | shift | x87 | sse_s | sse_p | sse_i | avx | fma | cmov):
            return True
        if mnem.startswith('rep '):
            return True
        return False
    except Exception:
        return False

# ---- CONSTANT/STRING COUNTING (LIGHTWEIGHT, FAST) ----
def extract_constants_from_instruction(addr, seen, string_addrs):
    res = {'numeric': 0, 'string': 0}
    try:
        mnem = get_base_mnemonic(addr)
        if mnem in {'nop','ret','leave','int3','hlt','clc','stc','cld','std'}:
            return res
        for i in range(6):
            t = idc.get_operand_type(addr, i)
            if t == idaapi.o_void:
                break
            v = idc.get_operand_value(addr, i)
            if t == idaapi.o_imm:
                # Simple filter for uninteresting small immediates
                if v not in (0,1,2,4,8,16,32,64,255,256,512,1024) and not (-256 <= v < 0):
                    key = f"imm_{v}_{addr}"
                    if key not in seen:
                        res['numeric'] += 1
                        seen.add(key)
                if v in string_addrs:
                    key = f"str_{v}_{addr}"
                    if key not in seen:
                        res['string'] += 1
                        seen.add(key)
            elif t in (idaapi.o_mem, idaapi.o_displ, idaapi.o_near, idaapi.o_far):
                if v in string_addrs:
                    key = f"str_{v}_{addr}"
                    if key not in seen:
                        res['string'] += 1
                        seen.add(key)
    except Exception:
        pass
    return res

# ------------------------- BASIC BLOCKS & CACHE -------------------------
class BBlock(object):
    """Basic block node: holds ATTR_NAMES-dim attributes + stats"""
    def __init__(self, func_ea, start_ea):
        self.func_ea = func_ea
        self.addr = start_ea
        # raw features
        self.imme = 0.0
        self.strc = 0.0
        self.mem  = 0.0
        self.arith= 0.0
        self.indeg= 0.0
        self.offsp= 0.0
        self.btw  = 0.0
        self.depth= 0.0
        self.ins  = 0
        # normalized features (z-score)
        self.imme_norm = 0.0
        self.strc_norm = 0.0
        self.mem_norm  = 0.0
        self.arith_norm= 0.0
        self.indeg_norm= 0.0
        self.offsp_norm= 0.0
        self.btw_norm  = 0.0
        self.depth_norm= 0.0

    def set_graph_metrics(self, indeg, offsp, btw):
        self.indeg = float(indeg)
        self.offsp = float(offsp)
        self.btw   = float(btw)

    def to_attr_list(self):
        return [self.imme, self.strc, self.mem, self.arith, self.indeg, self.offsp, self.btw, self.depth]

    def to_attr_list_norm(self):
        return [self.imme_norm, self.strc_norm, self.mem_norm, self.arith_norm, 
                self.indeg_norm, self.offsp_norm, self.btw_norm, self.depth_norm]

class BBWrapper(object):
    def __init__(self, ea, bb): self.ea_ = ea; self.bb_ = bb
    def get_bb(self): return self.bb_
    def __lt__(self, o): return self.ea_ < o.ea_
    def __eq__(self, o): return self.ea_ == o.ea_

class BBCache(object):
    """BB cache sorted by start EA + binary search"""
    def __init__(self):
        self.arr = []
        for f in idautils.Functions():
            fn = idaapi.get_func(f)
            if not fn: continue
            for bb in idaapi.FlowChart(fn, flags=idaapi.FC_PREDS):
                self.arr.append(BBWrapper(bb.start_ea, bb))
        self.arr.sort(key=lambda x: x.ea_)

    def get_cache_size(self): return len(self.arr)

    def find_block(self, ea):
        # bisect_right
        lo, hi = 0, len(self.arr)
        while lo < hi:
            mid = (lo + hi)//2
            if ea < self.arr[mid].ea_:
                hi = mid
            else:
                lo = mid + 1
        if lo == 0: return None
        cand = self.arr[lo-1].get_bb()
        if cand and cand.start_ea <= ea < cand.end_ea:
            return cand
        return None

# ----------------------- STANDARDIZE -----------------------
def _mean_std(xs):
    n = float(len(xs))
    if n == 0:
        return 0.0, 1.0
    mu = sum(xs) / n
    var = sum((x - mu) * (x - mu) for x in xs) / n   # population std
    sd = math.sqrt(var)

    if sd < 1e-12:
        sd = 1.0
    return mu, sd

def zscore_normalize_blocks(blocks):
    bblist = list(blocks.values())
    if not bblist:
        return

    imme_vals  = [b.imme  for b in bblist]
    strc_vals  = [b.strc  for b in bblist]
    mem_vals   = [b.mem   for b in bblist]
    arith_vals = [b.arith for b in bblist]
    indeg_vals = [b.indeg for b in bblist]
    offsp_vals = [b.offsp for b in bblist]
    btw_vals   = [b.btw   for b in bblist]
    depth_vals = [b.depth for b in bblist]

    mu_imme,  sd_imme  = _mean_std(imme_vals)
    mu_strc,  sd_strc  = _mean_std(strc_vals)
    mu_mem,   sd_mem   = _mean_std(mem_vals)
    mu_arith, sd_arith = _mean_std(arith_vals)
    mu_indeg, sd_indeg = _mean_std(indeg_vals)
    mu_offsp, sd_offsp = _mean_std(offsp_vals)
    mu_btw,   sd_btw   = _mean_std(btw_vals)
    mu_depth, sd_depth = _mean_std(depth_vals)

    for b in bblist:
        b.imme_norm  = (b.imme  - mu_imme)  / sd_imme
        b.strc_norm  = (b.strc  - mu_strc)  / sd_strc
        b.mem_norm   = (b.mem   - mu_mem)   / sd_mem
        b.arith_norm = (b.arith - mu_arith) / sd_arith
        b.indeg_norm = (b.indeg - mu_indeg) / sd_indeg
        b.offsp_norm = (b.offsp - mu_offsp) / sd_offsp
        b.btw_norm   = (b.btw   - mu_btw)   / sd_btw
        b.depth_norm = (b.depth - mu_depth) / sd_depth

# ----------------------- APAGERANK (Attributed PageRank) -----------------------
def _get_norm_attr(b, name):
    if name == "imme":
        return b.imme_norm
    if name == "strc":
        return b.strc_norm
    if name == "mem":
        return b.mem_norm
    if name == "arith":
        return b.arith_norm
    if name == "indeg":
        return b.indeg_norm
    if name == "offsp":
        return b.offsp_norm
    if name == "btw":
        return b.btw_norm
    if name == "depth":
        return b.depth_norm
    raise KeyError(f"Unknown attribute name: {name}")


def _set_norm_attr(b, name, val):
    if name == "imme":
        b.imme_norm = float(val); return
    if name == "strc":
        b.strc_norm = float(val); return
    if name == "mem":
        b.mem_norm = float(val); return
    if name == "arith":
        b.arith_norm = float(val); return
    if name == "indeg":
        b.indeg_norm = float(val); return
    if name == "offsp":
        b.offsp_norm = float(val); return
    if name == "btw":
        b.btw_norm = float(val); return
    if name == "depth":
        b.depth_norm = float(val); return
    raise KeyError(f"Unknown attribute name: {name}")


def run_apagerank(CFG, blocks, attr_names,
                  damping=APAGERANK_DAMPING,
                  gamma=APAGERANK_GAMMA,
                  tau=APAGERANK_TAU,
                  epsilon=APAGERANK_EPSILON,
                  iter_max=APAGERANK_ITER_MAX):
    """
        w_{t+1}(x) = (1 - p) * w_t(x)
                     + p * sum_{(y,x) in E} w_t(y) / ( O(y) * (I(x) + τ)^γ )
    """
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
            b = blocks[n]
            w_prev[n] = float(_get_norm_attr(b, attr))

        if not w_prev:
            continue

        if VERBOSE:
            print(f"[+] APageRank: attr '{attr}' start, "
                  f"iters ≤ {iter_max}, eps={epsilon}")

        for it in range(iter_max):
            w_next = {}
            max_delta = 0.0

            for x in nodes:
                old_val = w_prev[x]
                acc = 0.0

                # sum_{(y,x) in E} ...
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
            _set_norm_attr(blocks[n], attr, val)

# ----------------------- SANCOV PC-TABLE EXTRACTION -----------------------
def collect_pcs_aligned_with_counters():
    pcs_start, pcs_end   = get_seg_bounds('__sancov_pcs')
    cnt_start, cnt_end   = get_seg_bounds('__sancov_cntrs')
    if pcs_start is None or cnt_start is None:
        raise RuntimeError('Could not find __sancov_pcs or __sancov_cntrs segments')

    target_count = int(cnt_end - cnt_start)   # 1 byte per counter
    if target_count <= 0:
        raise RuntimeError('__sancov_cntrs length is 0')

    pcs = []
    ea = pcs_start
    while ea + 8 <= pcs_end and len(pcs) < target_count:
        q = read_qword_safe(ea)
        if is_plausible_code_addr(q):
            pcs.append(q)
            ea += 16  # Typically followed by flags/guard qword
        else:
            ea += 8   # Skip padding/alignment
    if len(pcs) < target_count:
        log.warning(f"Only parsed {len(pcs)} PCs from __sancov_pcs, fewer than counters={target_count}; truncating to the smaller count")
    return pcs[:target_count]

# ------------------ TARGET-ONLY FUNCTION SET (REACHABLE FROM ENTRY) ------------------
def resolve_seed_entries(pcs):
    seeds = []
    for name in SEED_ENTRY_NAMES:
        ea = idc.get_name_ea_simple(name)
        if ea != idc.BADADDR:
            seeds.append(ea)
    if seeds:
        return list(set(seeds))

    # Fallback: use the function containing the first PC
    if pcs:
        bb_fn = idaapi.get_func(pcs[0])
        if bb_fn:
            return [bb_fn.start_ea]
    raise RuntimeError("No usable entry function found (neither LLVMFuzzerTestOneInput nor a function inferred from the first PC)")

def function_filter(f):
    """
    Lenient filter: keep normal .text non-thunk/non-lib functions.
    We DO NOT exclude by name (e.g., libafl-related); exclusion is achieved by reachability.
    """
    try:
        flags = idc.get_func_attr(f, idc.FUNCATTR_FLAGS)
        if flags == idc.BADADDR:
            return False
        if (flags & idc.FUNC_LIB) or (flags & idc.FUNC_THUNK):
            return False
        segname = idc.get_segm_name(f) or ''
        if segname.lower() not in ('.text','text','code','__text'):
            return False
        fn = idaapi.get_func(f)
        if fn and (fn.end_ea - fn.start_ea) < 4:
            return False
        return True
    except Exception:
        return False

def build_function_call_graph():
    """Build a global function-level call graph: func_start_ea -> set(of callee func_start_ea)"""
    call_graph = defaultdict(set)
    funcs = [f for f in idautils.Functions() if function_filter(f)]
    for f in funcs:
        fn = idaapi.get_func(f)
        if not fn: continue
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
            if cur == idc.BADADDR: break
    return call_graph

def reachable_from_seeds(call_graph, seeds):
    """BFS on the function-level graph to compute the target-only function set"""
    vis = set()
    q = deque()
    for s in seeds:
        if function_filter(s):
            vis.add(s); q.append(s)
    while q:
        u = q.popleft()
        for v in call_graph.get(u, ()):
            if v not in vis:
                vis.add(v); q.append(v)
    return vis

# --------------------- TARGET-ONLY CFG CONSTRUCTION & FEATURES ---------------------
def build_target_cfg_and_features(target_funcs):
    """
    Returns:
      - CFG: adjacency {bb_start_ea: set(successor_bb_start_ea)}
      - blocks: {bb_start_ea: BBlock}
      - func_of_bb: {bb_start_ea: func_start_ea}
    """
    CFG = defaultdict(set)
    blocks = {}
    func_of_bb = {}

    string_addrs = get_all_ida_strings()

    for f in target_funcs:
        fn = idaapi.get_func(f)
        if not fn: continue
        fc = idaapi.FlowChart(fn, flags=idaapi.FC_PREDS)
        # Pre-create BB nodes
        for bb in fc:
            b = BBlock(fn.start_ea, bb.start_ea)
            # Lightweight per-BB local feature counting (4 dims)
            seen = set()
            ea = bb.start_ea
            while ea < bb.end_ea and ea != idc.BADADDR:
                b.ins += 1
                c = extract_constants_from_instruction(ea, seen, string_addrs)
                b.imme  += float(c['numeric'])
                b.strc  += float(c['string'])
                mnem = get_base_mnemonic(ea)
                if is_memory_operation(ea, mnem):
                    b.mem += 1.0
                if is_arithmetic_operation(ea, mnem):
                    b.arith += 1.0
                ea = idc.next_head(ea)
                if ea == idc.BADADDR: break
            blocks[bb.start_ea] = b
            func_of_bb[bb.start_ea] = fn.start_ea

        # Add edges (only within/among target functions)
        for bb in fc:
            src = bb.start_ea
            for succ in bb.succs():
                dst = succ.start_ea
                # Target-domain BBs are present in `blocks`
                if src in blocks and dst in blocks:
                    CFG[src].add(dst)

    return CFG, blocks, func_of_bb

def compute_depth_attribute(CFG, blocks, func_of_bb, call_graph, seeds):
    """
    depth = function-call-depth(from any seed) + intra-function-BB-depth(from function entry bb)
    """
    # 1) function-call-depth by BFS on function call graph
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
    # 2) build per-function structures
    preds = defaultdict(set)
    for u, outs in CFG.items():
        for v in outs:
            preds[v].add(u)
    func_to_bbs = defaultdict(list)
    for bb_ea, f_ea in func_of_bb.items():
        func_to_bbs[f_ea].append(bb_ea)
    # find entry bb of each function: bb with no preds from same function (fallback: min addr)
    func_entry_bb = {}
    for f_ea, bb_list in func_to_bbs.items():
        entry_candidates = []
        sset = set(bb_list)
        for b in bb_list:
            if not (preds[b] & sset):
                entry_candidates.append(b)
        if entry_candidates:
            func_entry_bb[f_ea] = entry_candidates[0]
        else:
            func_entry_bb[f_ea] = min(bb_list)
    # 3) intra-function BFS for each function
    intra_depth = {}
    succ = CFG
    for f_ea, entry_bb in func_entry_bb.items():
        sset = set(func_to_bbs.get(f_ea, []))
        dist = defaultdict(lambda: INF)
        dq2 = deque([entry_bb])
        dist[entry_bb] = 0
        while dq2:
            x = dq2.popleft()
            for y in succ.get(x, ()):
                if y in sset and dist[y] == INF:
                    dist[y] = dist[x] + 1
                    dq2.append(y)
        for b in sset:
            intra_depth[b] = 0 if dist[b] == INF else dist[b]
    # 4) assign depth to each block
    for bb_ea, b in blocks.items():
        f_ea = func_of_bb.get(bb_ea, None)
        d_func = func_depth.get(f_ea, 0.0)
        d_intra = float(intra_depth.get(bb_ea, 0))
        b.depth = d_func + d_intra

def compute_graph_metrics_on_cfg(CFG, blocks):
    """
    On the TARGET-ONLY CFG compute:
      - indegree (exact)
      - offspring (number of reachable descendants)
      - betweenness (heuristic sampling)
    """
    # indegree
    indeg = defaultdict(int)
    for _, outs in CFG.items():
        for v in outs:
            indeg[v] += 1

    # offspring: BFS to count reachable descendants for each node
    # (For large graphs you may want memoization/topo speedups; this is a simple version.)
    nodes = list(blocks.keys())
    succ = CFG

    for n in nodes:
        seen = set()
        dq = deque()
        for v in succ.get(n, ()):
            if v not in seen:
                seen.add(v); dq.append(v)
        while dq:
            x = dq.popleft()
            for y in succ.get(x, ()):
                if y not in seen:
                    seen.add(y); dq.append(y)
        blocks[n].offsp = float(len(seen))

    # set indegree
    for n in nodes:
        blocks[n].indeg = float(indeg.get(n, 0))

    # betweenness (Brandes exact algorithm is slow for large graphs; use sampled sources)
    N = len(nodes)
    if N == 0:
        return
    sample_nodes = nodes
    if N > MAX_BETWEENNESS_SAMPLE:
        import random
        random.seed(0xC0FFEE)
        sample_nodes = random.sample(nodes, MAX_BETWEENNESS_SAMPLE)

    # Unweighted shortest-path based approximation
    btw_acc = defaultdict(float)

    # Simplified Brandes: BFS per source s to compute sigma/dist, then accumulate deltas
    for s in sample_nodes:
        S = []  # stack of nodes in order of nondecreasing distance
        P = defaultdict(list)  # predecessors
        sigma = defaultdict(float)
        sigma[s] = 1.0
        dist = defaultdict(lambda: -1)
        dist[s] = 0
        Q = deque([s])
        while Q:
            v = Q.popleft()
            S.append(v)
            for w in CFG.get(v, ()):
                # w discovered first time?
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    Q.append(w)
                # (v,w) is on a shortest path?
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    P[w].append(v)
        # Accumulation
        delta = defaultdict(float)
        while S:
            w = S.pop()
            for v in P[w]:
                if sigma[w] > 0:
                    delta_v = (sigma[v] / sigma[w]) * (1.0 + delta[w])
                    delta[v] += delta_v
            if w != s:
                btw_acc[w] += delta[w]

    # Approximate normalization to keep values roughly within [0,1]
    # (For directed graphs a factor like 1/((n-1)(n-2)) is typical; we scale by sample size and N.)
    norm = (len(sample_nodes) - 1) * (N - 1) if N > 1 else 1.0
    if norm <= 0: norm = 1.0
    for n in nodes:
        blocks[n].btw = float(btw_acc.get(n, 0.0) / norm)

def count_reachable_edges(CFG, func_of_bb, target_funcs):
    """
    count reachable edges for all functions that are reachable from entry of fuzzing harness
    """
    func_to_bbs = defaultdict(list)
    for bb, f in func_of_bb.items():
        if f in target_funcs:
            func_to_bbs[f].append(bb)

    succ = CFG
    total_edges = 0

    for f_ea, bbs in func_to_bbs.items():
        if not bbs:
            continue
        sset = set(bbs)

        preds = defaultdict(set)
        for u in sset:
            for v in succ.get(u, ()):
                if v in sset:
                    preds[v].add(u)
        entry_candidates = [b for b in bbs if not (preds[b] & sset)]
        entry_bb = entry_candidates[0] if entry_candidates else min(bbs)

        vis = set([entry_bb])
        dq = deque([entry_bb])
        while dq:
            u = dq.popleft()
            for v in succ.get(u, ()):
                if v in sset and v not in vis:
                    vis.add(v)
                    dq.append(v)

        for u in vis:
            total_edges += sum(1 for v in succ.get(u, ()) if v in vis)

    return int(total_edges)

# --------------------- FEATURES_MAP CONSTRUCTION & EXPORT ---------------------
def l2_norm(vec): return math.sqrt(sum(float(x)*float(x) for x in vec))

def _is_one_hot(u, tol=1e-12):
    """Return (is_one_hot, index). One-hot = exactly one non-zero entry (up to tol)."""
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
    """
    z_vals: normalized attributes vector
    u: weight vector; if None, use (1,...,1)/sqrt(d)
    New equation (allow negative):
        w = (z·u / ||u||_2) * ||z||_2
    Pure 1D (u is one-hot): w = z_i
    """
    if not z_vals:
        return 0.0
    d = len(z_vals)

    # 1D case: u is (scaled) one-hot -> return that coordinate directly (can be negative)
    if u is not None and len(u) == d:
        is_one_hot, idx = _is_one_hot(u)
        if is_one_hot:
            return float(z_vals[idx])

    # dot / ||u||
    if u is None or len(u) != d:
        dot_over_unorm = sum(float(z) for z in z_vals) / math.sqrt(d)
    else:
        u_norm = math.sqrt(sum(float(ui) * float(ui) for ui in u))
        if u_norm == 0.0:
            dot_over_unorm = sum(float(z) for z in z_vals) / math.sqrt(d)
        else:
            dot_over_unorm = sum(float(zi) * float(ui) for zi, ui in zip(z_vals, u)) / u_norm

    # ||z||
    mag = math.sqrt(sum(float(z) * float(z) for z in z_vals))

    # No clamping: allow negative and zero
    return dot_over_unorm * mag

# --------------------- store results ---------------------
def build_and_save_features_map(pcs, CFG, blocks, func_of_bb, reachable_edges=None):
    bin_path = ida_nalt.get_input_file_path()
    base = os.path.basename(bin_path)
    out_dir = os.path.dirname(bin_path) or os.getcwd()

    bb_cache = BBCache()

    fmap = []
    dbg = []
    target_bb_set = set(blocks.keys())

    def _attrs_raw_dict(b):
        return {
            "imme": float(b.imme),
            "strc": float(b.strc),
            "mem": float(b.mem),
            "arith": float(b.arith),
            "indeg": float(b.indeg),
            "offsp": float(b.offsp),
            "btw": float(b.btw),
            "depth": float(b.depth),
            "ins": int(b.ins),
        }

    def _attrs_norm_dict(b):
        return {
            "imme_norm": float(b.imme_norm),
            "strc_norm": float(b.strc_norm),
            "mem_norm": float(b.mem_norm),
            "arith_norm": float(b.arith_norm),
            "indeg_norm": float(b.indeg_norm),
            "offsp_norm": float(b.offsp_norm),
            "btw_norm": float(b.btw_norm),
            "depth_norm": float(b.depth_norm),
        }

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
            # w = l2_norm(b.to_attr_list_norm())
            w = directional_weight(b.to_attr_list_norm())
            if w == 0.0:
                w = EPS_NON_TARGET
            fmap.append(float(w))
            dbg.append({
                "index": idx,
                "pc": hex(pc),
                "bb_start": hex(start),
                "func": hex(b.func_ea),
                "attrs_raw": _attrs_raw_dict(b),
                "attrs_norm": _attrs_norm_dict(b),
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

    out_path = os.path.join(out_dir, f"{base}_features_map_default.json")
    with open(out_path, "w") as f:
        json.dump(fmap, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved features_map -> {out_path}")

    dbg_path = os.path.join(out_dir, f"{base}_features_map.debug.json")
    with open(dbg_path, "w") as f:
        json.dump({"reachable_edges": reachable_edges if reachable_edges is not None else None, 
                   "pcs": [hex(p) for p in pcs], "map": dbg}, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved debug map   -> {dbg_path}")

    return out_path, dbg_path

def build_and_save_features_map_for_u(pcs, blocks, func_of_bb, u, out_filename):
    """
    regarding u to calculate weight and store features_map to out_filename
    """
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


# ------------------------------ MAIN ------------------------------
def main():
    time_start = time.time()
    bin_path = ida_nalt.get_input_file_path()
    print(f"[+] Binary: {bin_path}")

    # 1) pc-table & counters
    pcs = collect_pcs_aligned_with_counters()
    print(f"[+] PCs collected (aligned with counters): {len(pcs)}")

    # 2) Resolve entries & reachable function set (target-only)
    seeds = resolve_seed_entries(pcs)
    seed_names = [idc.get_func_name(ea) or hex(ea) for ea in seeds]
    print(f"[+] Seed entries: {seed_names}")

    call_g = build_function_call_graph()
    target_funcs = reachable_from_seeds(call_g, seeds)
    print(f"[+] Target-only function count: {len(target_funcs)}")

    # 3) Build target-only CFG and extract local BB features on it
    CFG, blocks, func_of_bb = build_target_cfg_and_features(target_funcs)
    print(f"[+] Target-only CFG: {len(blocks)} basic blocks, {sum(len(v) for v in CFG.values())} edges")

    if len(blocks) == 0:
        raise RuntimeError("Target-only CFG is empty. Check entry points/reachability or build symbols.")

    # 4) Compute graph structural features on the target-only CFG
    print("[+] Computing graph metrics (indegree/offspring/betweenness) on target-only CFG ...")
    compute_graph_metrics_on_cfg(CFG, blocks)
    # Depth metric
    print("[+] Computing depth (from entry function) ...")
    compute_depth_attribute(CFG, blocks, func_of_bb, call_g, seeds)

    # 5) select feature type
    # feature = idaapi.ask_str("", 0, "Choose feature type (semantic/graph/both): ")
    feature = 'both'  # or 'graph' or 'both'
    if feature == "semantic":
        # only calculate semantic features (instruction types)
        print("[+] Computing only semantic features (instruction types) ...")
        for b in blocks.values():
            b.indeg = 0.0
            b.offsp = 0.0
            b.btw = 0.0
            b.depth = 0.0
    elif feature == "graph":
        # only calculate graph structure features
        print("[+] Computing only graph structure features (in-degree, offspring, betweenness) ...")
        for b in blocks.values():
            b.imme = 0.0
            b.strc = 0.0
            b.mem = 0.0
            b.arith = 0.0
    else:
        # calculate both features
        print("[+] Computing both semantic and graph features ...")
    
    # normalizing attributes with z-score
    zscore_normalize_blocks(blocks)

    # 6) Attributed PageRank
    if USE_APAGERANK:
        if feature == "semantic":
            ap_attrs = ["imme", "strc", "mem", "arith"]
        elif feature == "graph":
            ap_attrs = ["indeg", "offsp", "btw", "depth"]
        else:
            ap_attrs = ATTR_NAMES  # eight dims: semantic + graph

        print(f"[+] Running Attributed PageRank on attributes: {ap_attrs}")
        apagerank_time_start = time.time()
        run_apagerank(
            CFG,
            blocks,
            ap_attrs,
            damping=APAGERANK_DAMPING,
            gamma=APAGERANK_GAMMA,
            tau=APAGERANK_TAU,
            epsilon=APAGERANK_EPSILON,
            iter_max=APAGERANK_ITER_MAX,
        )
        apagerank_time_end = time.time()
        print(f'APageRank Time: {apagerank_time_end - apagerank_time_start} s')

    # count reachable edges
    reachable_edges = count_reachable_edges(CFG, func_of_bb, target_funcs)
    if VERBOSE:
        print(f"[+] Reachable edges from entries: {reachable_edges}")

    # 7) Build and export features_map
    # one-hot attributes weights
    base = os.path.basename(bin_path)
    out_dir = os.path.dirname(bin_path) or os.getcwd()
    attr_arrays = {}

    dim = len(ATTR_NAMES)
    for i, name in enumerate(ATTR_NAMES):
        u_one_hot = [0.0] * dim
        u_one_hot[i] = 1.0
        out_file = f"{base}_features_map_{name}.json"
        fmap, _ = build_and_save_features_map_for_u(pcs, blocks, func_of_bb, u_one_hot, out_file)
        attr_arrays[name] = fmap

    merged_path = os.path.join(out_dir, f"{base}_features_map.json")
    with open(merged_path, "w") as f:
        json.dump(attr_arrays, f, indent=2)
    if VERBOSE:
        print(f"[+] Saved merged single-attr dict -> {merged_path}")

    # default attributes weights
    out_map, out_dbg = build_and_save_features_map(pcs, CFG, blocks, func_of_bb, reachable_edges)

    time_end = time.time()
    print("\n[+] DONE.")
    print(f"    Blocks: {len(blocks)}")
    print(f"    Map   : {out_map}")
    print(f"    Debug : {out_dbg}")
    print(f"    Time  : {(time_end - time_start):.2f}s")


if __name__ == "__main__":
    main()
