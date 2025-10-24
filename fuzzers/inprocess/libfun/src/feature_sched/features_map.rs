/*
feature_sched/features_map.rs: load and parse the features_map.json data
*/
use serde::Deserialize;
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

pub static V_CANDIDATES: Lazy<RwLock<Vec<Vec<f64>>>> = Lazy::new(|| RwLock::new(Vec::new()));
pub static CURRENT_V: Lazy<RwLock<Vec<f64>>> = Lazy::new(|| RwLock::new(Vec::new()));

fn ensure_v_candidates_for(features_map_path: &Path) {
    let mut guard = V_CANDIDATES.write().unwrap();
    if !guard.is_empty() {
        return;
    }
    let d = ATTR_ORDER.len();

    if let Some((dir, target)) = derive_dir_and_target(features_map_path) {
        let cand_path = dir.join(format!("{}_v_candidates.json", target));
        eprintln!("Reading v candidates file: {}", cand_path.display());
        if let Ok(cands) = load_candidates_from(&cand_path, d) {
            *guard = cands;
            return;
        }
    }

    *guard = default_candidates(d);
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

pub fn load_and_align_features_map(path: &Path, sites: usize) -> std::io::Result<Vec<f64>> {
    ensure_v_candidates_for(path);

    let mut f = File::open(path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;

    let v0: Vec<f64> = {
        let g = V_CANDIDATES.read().unwrap();
        if let Some(first) = g.first() {
            first.clone()
        } else {
            let d = ATTR_ORDER.len();
            vec![1.0 / (d as f64).sqrt(); d]
        }
    };
    {
        let mut curv = CURRENT_V.write().unwrap();
        *curv = v0.clone();
    }

    let feat: Vec<f64> = match serde_json::from_str::<FeatsJson>(&s).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json parse err: {e}"))
    })? {
        FeatsJson::Raw(feat) => feat,
        FeatsJson::Obj { features } => features,
        FeatsJson::Dict(map) => combine_feature_matrix_to_weights(map, &v0),
    };

    Ok(align(feat, sites))
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
