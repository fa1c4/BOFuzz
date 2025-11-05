/*
feature_sched/features_map.rs: load and parse the features_map.json data
*/
use serde::{Serialize, Deserialize};
use crate::feature_sched::metadata::{FeaturesMapMeta, FeaturesMatrixMeta};
use crate::feature_sched::{replace_v_candidates, get_alpha_init, set_current_weight_vec, 
        get_v_candidates, set_tpe_satisfied, get_factor_params, get_current_weight_vec};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process,
    cmp::min,
};
use once_cell::sync::Lazy;
use std::sync::RwLock;
use libafl::Error;
use libafl::common::HasMetadata;

#[derive(Deserialize)]
#[serde(untagged)]
enum FeatsJson {
    // only array
    Raw(Vec<f64>),
    // {"features": [...]}
    Obj { features: Vec<f64> },
    // ATTR_NUM Dim matricx
    Dict(HashMap<String, Vec<f64>>),
}

const ATTR_ORDER: [&str; 8] = ["imme", "strc", "mem", "arith", "indeg", "offsp", "btw", "depth"];

const DEFAULT_PRIOR_8: [usize; 8] = [6, 0, 5, 1, 2, 3, 4, 7];

fn normalize_prior_order(mut raw: Vec<usize>, d: usize) -> Option<Vec<usize>> {
    if raw.is_empty() { return None; }
    let zero_based = raw.iter().all(|&x| x < d);
    let one_based  = raw.iter().all(|&x| x >= 1 && x <= d);

    if !zero_based && !one_based {
        return None;
    }
    if one_based {
        for x in &mut raw { *x -= 1; } // 1-based to 0-based
    }

    let mut seen = std::collections::HashSet::with_capacity(d);
    let mut ord = Vec::with_capacity(d);
    for &idx in &raw {
        if idx < d && seen.insert(idx) {
            ord.push(idx);
        }
    }
    
    for i in 0..d {
        if seen.insert(i) {
            ord.push(i);
        }
    }
    
    ord.truncate(d);
    Some(ord)
}

fn load_prior_order_from(path: &Path, d: usize) -> Option<Vec<usize>> {
    let mut f = File::open(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    let raw: Vec<usize> = serde_json::from_str(&s).ok()?;
    normalize_prior_order(raw, d)
}

fn one_hot(d: usize, idx: usize) -> Vec<f64> {
    let mut v = vec![0.0; d];
    if idx < d { v[idx] = 1.0; }
    v
}

fn default_candidates_with_order(d: usize, order: &[usize]) -> Vec<Vec<f64>> {
    let mut res = Vec::with_capacity(d + 1);
    for &idx in order.iter().take(d) {
        res.push(one_hot(d, idx));
    }
    res.push(uniform_vec(d));
    res
}

fn ensure_v_candidates_for<S: HasMetadata>(state: &mut S, features_map_path: &Path) {
    if !get_v_candidates(state).is_empty() { return; }

    let dims = ATTR_ORDER.len(); // default as 8

    let prior_order: Vec<usize> = match derive_dir_and_target(features_map_path) {
        Some((dir, tgt)) => {
            let pri_path = dir.join(format!("{}_prior_order.json", tgt));
            match load_prior_order_from(&pri_path, dims) {
                Some(v) => {
                    eprintln!("Reading prior order file: {}", pri_path.display());
                    eprintln!("Prior Order: {:?}", v);
                    v
                }
                None => {
                    eprintln!(
                        "No valid prior order at {}, using DEFAULT_PRIOR_8.",
                        pri_path.display()
                    );
                    DEFAULT_PRIOR_8.to_vec()
                }
            }
        }
        None => {
            eprintln!("Cannot derive prior-order path, using DEFAULT_PRIOR_8.");
            DEFAULT_PRIOR_8.to_vec()
        }
    };

    let cands8: Vec<Vec<f64>> = match derive_dir_and_target(features_map_path) {
        Some((dir, tgt)) => {
            let cand_path = dir.join(format!("{}_v_candidates.json", tgt));
            match load_candidates_from(&cand_path, dims) {
                Ok(v) if !v.is_empty() => {
                    eprintln!("Reading v candidates file: {}", cand_path.display());
                    v
                }
                _ => {
                    eprintln!(
                        "No v-candidates file provided or empty ({}), using defaults.",
                        cand_path.display()
                    );
                    default_candidates_with_order(dims, &prior_order)
                }
            }
        }
        None => {
            eprintln!(
                "Cannot derive v-candidates path from {}, using defaults.",
                features_map_path.display()
            );
            default_candidates_with_order(dims, &prior_order)
        }
    };

    // read alpha init
    let alpha0 = get_alpha_init(state);
    let alpha = if alpha0.is_finite() { alpha0 } else { 0.5 }.clamp(0.0, 1.0);
    let cands9: Vec<Vec<f64>> = cands8
        .into_iter()
        .map(|v8| {
            let mut v = Vec::with_capacity(1 + v8.len());
            v.push(alpha);
            v.extend(v8);
            v
        })
        .collect();

    replace_v_candidates(state, cands9);

    let v0_9 = get_v_candidates(state)
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            let mut v = vec![alpha];
            v.extend(uniform_vec(8));
            v
        });

    if get_current_weight_vec(state).is_empty() {
        set_current_weight_vec(state, v0_9);
    }
}

fn load_candidates_from(path: &Path, d: usize) -> std::io::Result<Vec<Vec<f64>>> {
    let mut f = File::open(path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let mut arr: Vec<Vec<f64>> = serde_json::from_str(&s).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("v_candidates json parse err: {e}"))
    })?;

    for v in &mut arr {
        if v.len() < d {
            v.resize(d, 0.0);
        } else if v.len() > d {
            v.truncate(d);
        }
        // truncate to [0, 1]
        for w in v.iter_mut() {
            if !w.is_finite() { *w = 0.0; }
            if *w < 0.0 { *w = 0.0; }
            if *w > 1.0 { *w = 1.0; }
        }
        // uniform
        let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm > 0.0 {
            for w in v.iter_mut() { *w /= norm; }
        } else {
            *v = uniform_vec(d);
        }
    }

    if arr.is_empty() {
        arr.push(uniform_vec(d));
    }
    Ok(arr)
}

fn default_candidates(d: usize) -> Vec<Vec<f64>> {
    let mut res = vec![uniform_vec(d)];
    for i in 0..d {
        let mut e = vec![0.0f64; d];
        e[i] = 1.0;
        res.push(e);
    }
    res
}

fn uniform_vec(d: usize) -> Vec<f64> {
    let v = 1.0f64 / (d as f64).sqrt();
    vec![v; d]
}

fn derive_dir_and_target(p: &Path) -> Option<(PathBuf, String)> {
    let dir = p.parent()?.to_path_buf();
    let file = p.file_name()?.to_string_lossy();
    let needle = "_features_map";
    if let Some(idx) = file.find(needle) {
        let tgt = file[..idx].to_string();
        Some((dir, tgt))
    } else {
        let stem = p.file_stem()?.to_string_lossy().to_string();
        Some((dir, stem))
    }
}

pub fn load_and_align_features_map<S: HasMetadata>(
    state: &mut S,
    path: &Path, 
    sites: usize,
) -> std::io::Result<(
    Vec<f64>, 
    Option<std::collections::HashMap<String, Vec<f64>>>,
)> {
    ensure_v_candidates_for(state, path);

    let mut f = File::open(path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;

    let v0_8: Vec<f64> = get_v_candidates(state)
        .first()
        .map(|v9| v9[1..].to_vec()) // get rid of alpha
        .unwrap_or_else(|| vec![1.0 / (ATTR_ORDER.len() as f64).sqrt(); ATTR_ORDER.len()]);
    
    let (feats_raw, matrix_opt, tpe_sat) =
        match serde_json::from_str::<FeatsJson>(&s).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json parse err: {e}"))
        })? {
            FeatsJson::Raw(feat) => (feat, None, false),
            FeatsJson::Obj { features } => (features, None, false),
            FeatsJson::Dict(map) => {
                let feats = combine_feature_matrix_to_weights(map.clone(), &v0_8);
                (feats, Some(map), true)
            }
        };

    set_tpe_satisfied(state, tpe_sat);
    if tpe_sat {
        let alpha = get_factor_params(state).alpha;
        let mut v9 = Vec::with_capacity(1 + v0_8.len());
        v9.push(alpha.clamp(0.0, 1.0));
        v9.extend_from_slice(&v0_8);
        set_current_weight_vec(state, v9);
    }

    Ok((align(feats_raw, sites), matrix_opt))
}

fn align(mut v: Vec<f64>, sites: usize) -> Vec<f64> {
    if v.len() < sites { v.resize(sites, 0.0); }
    if v.len() > sites { v.truncate(sites); }
    v
}

fn prepare_v(v_raw: &[f64], d: usize) -> Vec<f64> {
    let mut v = vec![0.0; d];
    let n = min(d, v_raw.len());
    for i in 0..n {
        let mut w = v_raw[i];
        if !w.is_finite() { w = 0.0; }
        if w < 0.0 { w = 0.0; }
        if w > 1.0 { w = 1.0; }
        v[i] = w;
    }
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for w in v.iter_mut() { *w /= norm; }
        v
    } else {
        let u = 1.0 / (d as f64).sqrt();
        vec![u; d]
    }
}
// weight_i = ((z_i ⋅ v) / sqrt(d)) * ||z_i||_2
pub fn combine_feature_matrix_to_weights(
    map: HashMap<String, Vec<f64>>,
    v_in: &[f64],
) -> Vec<f64> {
    let d = ATTR_ORDER.len();
    let inv_sqrt_d = 1.0f64 / (d as f64).sqrt();
    let v = prepare_v(v_in, d);

    // check every dim exists
    for key in &ATTR_ORDER {
        if !map.contains_key(*key) {
            eprintln!("error: missing feature dimension '{}'", key);
            process::exit(1);
        }
    }
    // check lengths are equal
    let expected_len = map.get(ATTR_ORDER[0]).unwrap().len();
    for key in &ATTR_ORDER {
        let len = map.get(*key).unwrap().len();
        if len != expected_len {
            eprintln!(
                "error: feature dimension length mismatch: '{}' has len {}, expected {}",
                key, len, expected_len
            );
            process::exit(1);
        }
    }
    let n = expected_len;

    // weight calculation
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut z = vec![0.0f64; d];
        for (j, key) in ATTR_ORDER.iter().enumerate() {
            z[j] = map.get(*key).unwrap()[i];
        }
        let mag = z.iter().map(|x| x * x).sum::<f64>().sqrt();
        let dot = z.iter().zip(v.iter()).map(|(a, b)| a * b).sum::<f64>();
        let w = (dot * inv_sqrt_d) * mag;
        out.push(w);
    }
    out
}

pub fn apply_v_to_features<S: HasMetadata>(state: &mut S, v: &[f64]) -> Result<(), Error> {
    // only input is matrix then recompute features_map
    let (feats, sites) = match state.metadata_map().get::<FeaturesMatrixMeta>() {
        Some(m) => {
            let feats = combine_feature_matrix_to_weights(m.matrix.clone(), v);
            (feats, m.sites)
        }
        None => {
            // Flat input then skip
            let feats = state.metadata_map()
                .get::<FeaturesMapMeta>()
                .map(|m| m.feats.clone())
                .unwrap_or_default();
            let sites = feats.len();
            (feats, sites)
        }
    };

    let aligned = align(feats, sites);
    if state.metadata_map().get::<FeaturesMapMeta>().is_some() {
        let m = state.metadata_map_mut().get_mut::<FeaturesMapMeta>().unwrap();
        m.feats = aligned;
    } else {
        state.add_metadata(FeaturesMapMeta { feats: aligned });
    }

    // update v
    if !v.is_empty() {
        let alpha = get_factor_params(state).alpha; // 或 get_alpha_init(&state)
        let mut v9 = Vec::with_capacity(1 + v.len());
        v9.push(alpha.clamp(0.0, 1.0));
        v9.extend(v);
        set_current_weight_vec(state, v9);
    }
    
    Ok(())
}
