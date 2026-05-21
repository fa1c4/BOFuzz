use libafl::common::HasMetadata;
use libafl::Error;

use super::metadata::{BitSet, FrontierMeta, SancovAcfgMeta, TpeIterationMeta};

pub fn bitset_from_indices(len: usize, indices: &[usize]) -> BitSet {
    let mut out = vec![false; len];
    for &i in indices {
        if i < len {
            out[i] = true;
        }
    }
    out
}

pub fn bitset_get(bits: &[bool], idx: usize) -> bool {
    bits.get(idx).copied().unwrap_or(false)
}

pub fn recompute_frontier_sets(covered: &[bool], acfg: &SancovAcfgMeta) -> (BitSet, BitSet) {
    let n = acfg.n_sancov_sites;
    let mut f_prev = vec![false; n];
    let mut f_next = vec![false; n];

    for u in 0..n {
        if bitset_get(covered, u) {
            if acfg
                .successors
                .get(u)
                .into_iter()
                .flatten()
                .any(|&v| v < n && !bitset_get(covered, v))
            {
                f_prev[u] = true;
            }
        } else if acfg
            .predecessors
            .get(u)
            .into_iter()
            .flatten()
            .any(|&p| p < n && bitset_get(covered, p))
        {
            f_next[u] = true;
        }
    }

    (f_prev, f_next)
}

pub fn update_frontier_meta<S: HasMetadata>(
    state: &mut S,
    newly_covered: &[usize],
) -> Result<bool, Error> {
    let Some(acfg) = state.metadata_map().get::<SancovAcfgMeta>().cloned() else {
        return Ok(false);
    };
    let n = acfg.n_sancov_sites;
    let iteration = state
        .metadata_map()
        .get::<TpeIterationMeta>()
        .map(|m| m.current_iteration)
        .unwrap_or(0);

    let mut meta = state
        .metadata_map()
        .get::<FrontierMeta>()
        .cloned()
        .unwrap_or_else(|| FrontierMeta {
            iteration,
            covered: vec![false; n],
            f_prev: vec![false; n],
            f_next: vec![false; n],
        });

    if meta.covered.len() != n {
        meta.covered.resize(n, false);
    }

    let mut changed = false;
    for &idx in newly_covered {
        if idx < n && !meta.covered[idx] {
            meta.covered[idx] = true;
            changed = true;
        }
    }

    if changed {
        let (f_prev, f_next) = recompute_frontier_sets(&meta.covered, &acfg);
        meta.iteration = iteration;
        meta.f_prev = f_prev;
        meta.f_next = f_next;
        state.add_metadata(meta);
    }

    Ok(changed)
}

pub fn local_frontier_nodes(
    newly_covered: &[usize],
    testcase_covered: &[usize],
    acfg: &SancovAcfgMeta,
) -> Vec<usize> {
    let n = acfg.n_sancov_sites;
    let testcase_bits = bitset_from_indices(n, testcase_covered);
    let mut out_bits = vec![false; n];

    for &node in newly_covered {
        if node >= n {
            continue;
        }
        out_bits[node] = true;
        if let Some(preds) = acfg.predecessors.get(node) {
            for &p in preds {
                if p < n && bitset_get(&testcase_bits, p) {
                    out_bits[p] = true;
                }
            }
        }
    }

    out_bits
        .into_iter()
        .enumerate()
        .filter_map(|(i, set)| if set { Some(i) } else { None })
        .collect()
}
