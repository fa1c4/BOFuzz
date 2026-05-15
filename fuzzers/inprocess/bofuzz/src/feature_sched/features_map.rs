use crate::feature_sched::metadata::{
    FeatureSchemaFile, FeatureSpec, FeaturesMapMeta, FeaturesMatrixMeta,
};
use crate::feature_sched::{
    get_active_dim, get_active_feature_names, get_alpha_init, get_current_weight_vec,
    get_factor_params, get_v_candidates, replace_v_candidates, set_current_weight_vec,
    set_tpe_satisfied,
};
use libafl::common::HasMetadata;
use libafl::Error;
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const LEGACY_KEYS: &[&str] = &[
    "imme", "strc", "mem", "arith", "indeg", "offsp", "btw", "depth",
];

pub fn load_and_validate_schema(path: &Path) -> Result<FeatureSchemaFile, String> {
    let mut f = File::open(path).map_err(|e| {
        format!(
            "BOFuzz feature schema error: missing required file {}: {}",
            path.display(),
            e
        )
    })?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| {
        format!(
            "BOFuzz feature schema error: cannot read {}: {}",
            path.display(),
            e
        )
    })?;
    let schema: FeatureSchemaFile = serde_json::from_str(&s).map_err(|e| {
        format!(
            "BOFuzz feature schema error: invalid JSON in {}: {}",
            path.display(),
            e
        )
    })?;

    if schema.schema_version != 3 {
        return Err(format!(
            "BOFuzz feature schema error: schema_version must be 3, got {}",
            schema.schema_version
        ));
    }
    if schema.features.is_empty() {
        return Err("BOFuzz feature schema error: features list is empty".to_string());
    }

    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    for f in &schema.features {
        if !ids.insert(&f.id) {
            return Err(format!(
                "BOFuzz feature schema error: duplicate feature id '{}'",
                f.id
            ));
        }
        if !names.insert(&f.name) {
            return Err(format!(
                "BOFuzz feature schema error: duplicate feature name '{}'",
                f.name
            ));
        }
    }

    let all_canonical: std::collections::HashSet<&str> =
        schema.features.iter().map(|f| f.name.as_str()).collect();
    for f in &schema.features {
        if let Some(aliases) = &f.aliases {
            for alias in aliases {
                if all_canonical.contains(alias.as_str()) && alias != &f.name {
                    return Err(format!(
                        "BOFuzz feature schema error: alias '{}' for {} collides with canonical name",
                        alias, f.id
                    ));
                }
            }
        }
    }

    Ok(schema)
}

pub fn parse_vec_mask(raw: &str, schema_len: usize) -> Result<Vec<bool>, String> {
    let trimmed = raw.trim();

    let values: Vec<u8> = if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        inner
            .split(',')
            .map(|s| {
                s.trim()
                    .parse::<u8>()
                    .map_err(|_| "BOFuzz vec-mask error: non-binary value in mask".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
    } else if trimmed.contains(',') {
        trimmed
            .split(',')
            .map(|s| {
                s.trim()
                    .parse::<u8>()
                    .map_err(|_| "BOFuzz vec-mask error: non-binary value in mask".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        trimmed
            .chars()
            .map(|c| match c {
                '0' => Ok(0u8),
                '1' => Ok(1u8),
                _ => Err(format!(
                    "BOFuzz vec-mask error: non-binary value '{}' in mask",
                    c
                )),
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    for &v in &values {
        if v > 1 {
            return Err("BOFuzz vec-mask error: non-binary value in mask".to_string());
        }
    }

    if values.len() != schema_len {
        return Err(format!(
            "BOFuzz vec-mask error: mask length {} != schema feature length {} from features_schema.json",
            values.len(), schema_len
        ));
    }

    let mask: Vec<bool> = values.iter().map(|&v| v == 1).collect();

    if mask.iter().all(|&v| !v) {
        return Err(
            "BOFuzz vec-mask error: all-zero mask disables every schema feature".to_string(),
        );
    }

    Ok(mask)
}

pub fn compute_active_features(schema: &FeatureSchemaFile, mask: &[bool]) -> Vec<FeatureSpec> {
    schema
        .features
        .iter()
        .zip(mask.iter())
        .filter(|(_, &m)| m)
        .map(|(f, _)| f.clone())
        .collect()
}

/// Load and validate a feature map, returning a canonicalized map where every
/// key is the canonical schema feature name. Alias keys (e.g. "betweenness")
/// are resolved to their canonical name (e.g. "centrality"). Legacy keys and
/// unknown keys are rejected.
pub fn load_and_validate_feature_map(
    path: &Path,
    schema: &FeatureSchemaFile,
    sancov_sites: usize,
) -> Result<HashMap<String, Vec<f64>>, String> {
    let mut f = File::open(path).map_err(|e| {
        format!(
            "BOFuzz feature-map error: cannot open {}: {}",
            path.display(),
            e
        )
    })?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| {
        format!(
            "BOFuzz feature-map error: cannot read {}: {}",
            path.display(),
            e
        )
    })?;

    let map: HashMap<String, serde_json::Value> = serde_json::from_str(&s)
        .map_err(|e| format!("BOFuzz feature-map error: invalid JSON: {}", e))?;

    if map.contains_key("features") {
        return Err(
            "BOFuzz feature-map error: legacy {\"features\": [...]} format not supported"
                .to_string(),
        );
    }

    // Build the set of allowed keys: canonical names + declared aliases
    let mut allowed_keys: HashMap<&str, &str> = HashMap::new(); // map_key -> canonical_name
    for spec in &schema.features {
        allowed_keys.insert(spec.name.as_str(), spec.name.as_str());
        if let Some(aliases) = &spec.aliases {
            for alias in aliases {
                allowed_keys.insert(alias.as_str(), spec.name.as_str());
            }
        }
    }

    // Reject legacy and unknown keys
    for key in map.keys() {
        if LEGACY_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "BOFuzz feature-map error: legacy key '{}' is not supported; use canonical schema feature names",
                key
            ));
        }
        if !allowed_keys.contains_key(key.as_str()) {
            return Err(format!(
                "BOFuzz feature-map error: unknown key '{}' not in schema",
                key
            ));
        }
    }

    let mut result: HashMap<String, Vec<f64>> = HashMap::new();
    let mut expected_len: Option<usize> = None;

    for spec in &schema.features {
        // Resolve: try canonical name first, then aliases
        let resolved_map_key = if map.contains_key(&spec.name) {
            Some(spec.name.as_str())
        } else if let Some(aliases) = &spec.aliases {
            aliases
                .iter()
                .find(|a| map.contains_key(a.as_str()))
                .map(|a| a.as_str())
        } else {
            None
        };

        let map_key = resolved_map_key.ok_or_else(|| {
            format!(
                "BOFuzz feature-map error: missing feature {} {}",
                spec.id, spec.name
            )
        })?;

        let arr_val = map.get(map_key).unwrap();
        let arr: Vec<f64> = match arr_val {
            serde_json::Value::Array(a) => a
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    v.as_f64().ok_or_else(|| {
                        format!(
                            "BOFuzz feature-map error: feature {} {} contains non-numeric value at index {}",
                            spec.id, spec.name, i
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(format!(
                    "BOFuzz feature-map error: feature {} {} is not an array",
                    spec.id, spec.name
                ))
            }
        };

        for (i, &v) in arr.iter().enumerate() {
            if !v.is_finite() {
                return Err(format!(
                    "BOFuzz feature-map error: feature {} {} contains non-finite value at index {}",
                    spec.id, spec.name, i
                ));
            }
        }

        match expected_len {
            None => expected_len = Some(arr.len()),
            Some(el) if arr.len() != el => {
                return Err(format!(
                    "BOFuzz feature-map error: feature {} {} length {} != expected {}",
                    spec.id,
                    spec.name,
                    arr.len(),
                    el
                ));
            }
            _ => {}
        }

        // Always store under canonical name, even if the map used an alias
        result.insert(spec.name.clone(), arr);
    }

    if let Some(el) = expected_len {
        if el != sancov_sites {
            return Err(format!(
                "BOFuzz feature-map error: feature array length {} != sancov_sites {}",
                el, sancov_sites
            ));
        }
    }

    Ok(result)
}

fn one_hot(d: usize, idx: usize) -> Vec<f64> {
    let mut v = vec![0.0; d];
    if idx < d {
        v[idx] = 1.0;
    }
    v
}

fn uniform_vec(d: usize) -> Vec<f64> {
    if d == 0 {
        return Vec::new();
    }
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

fn load_candidates_from(path: &Path, active_dim: usize) -> Result<Vec<Vec<f64>>, String> {
    let mut f = File::open(path).map_err(|e| {
        format!(
            "BOFuzz candidate error: cannot open {}: {}",
            path.display(),
            e
        )
    })?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| {
        format!(
            "BOFuzz candidate error: cannot read {}: {}",
            path.display(),
            e
        )
    })?;
    let arr: Vec<Vec<f64>> = serde_json::from_str(&s).map_err(|e| {
        format!(
            "BOFuzz candidate error: invalid JSON in {}: {}",
            path.display(),
            e
        )
    })?;

    if arr.is_empty() {
        return Err(format!(
            "BOFuzz candidate error: {} contains empty candidate list",
            path.display()
        ));
    }

    let expected_len = 1 + active_dim;
    for (i, cand) in arr.iter().enumerate() {
        if cand.len() != expected_len {
            return Err(format!(
                "BOFuzz candidate error: candidate {} length {} != expected {} (1 + active_dim={})",
                i,
                cand.len(),
                expected_len,
                active_dim
            ));
        }
        for (j, &v) in cand.iter().enumerate() {
            if !v.is_finite() {
                return Err(format!(
                    "BOFuzz candidate error: candidate {} contains non-finite value at index {}",
                    i, j
                ));
            }
        }
        let weights = &cand[1..];
        let norm = weights.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm == 0.0 {
            return Err(format!(
                "BOFuzz candidate error: candidate {} active weights have zero norm",
                i
            ));
        }
    }

    Ok(arr)
}

fn generate_default_candidates(active_dim: usize, alpha: f64) -> Vec<Vec<f64>> {
    let mut res = Vec::with_capacity(active_dim + 1);

    // candidate 0: uniform active vector
    let mut uniform = Vec::with_capacity(1 + active_dim);
    uniform.push(alpha);
    uniform.extend(uniform_vec(active_dim));
    res.push(uniform);

    // candidates 1..N: one-hot in active schema order
    for i in 0..active_dim {
        let mut v = Vec::with_capacity(1 + active_dim);
        v.push(alpha);
        v.extend(one_hot(active_dim, i));
        res.push(v);
    }

    res
}

/// Load or generate candidate vectors. Candidate file absent -> defaults.
/// Candidate file present but invalid -> fatal error (returns Err).
pub fn ensure_v_candidates_for<S: HasMetadata>(
    state: &mut S,
    features_map_path: &Path,
    active_dim: usize,
) -> Result<(), String> {
    if !get_v_candidates(state).is_empty() {
        return Ok(());
    }

    let alpha0 = get_alpha_init(state);
    let alpha = if alpha0.is_finite() { alpha0 } else { 0.5 }.clamp(0.0, 1.0);

    let cands = match derive_dir_and_target(features_map_path) {
        Some((dir, tgt)) => {
            let cand_path = dir.join(format!("{}_v_candidates.json", tgt));
            if cand_path.exists() {
                // File exists -> must be valid, fatal on error
                let file_cands = load_candidates_from(&cand_path, active_dim).map_err(|e| {
                    format!(
                        "BOFuzz candidate error: invalid {}: {}",
                        cand_path.display(),
                        e
                    )
                })?;
                eprintln!(
                    "[BOFuzz] Reading v candidates file: {}",
                    cand_path.display()
                );
                file_cands
            } else {
                eprintln!(
                    "[BOFuzz] No v-candidates file at {}, generating defaults.",
                    cand_path.display()
                );
                generate_default_candidates(active_dim, alpha)
            }
        }
        None => {
            eprintln!("[BOFuzz] Cannot derive v-candidates path, generating defaults.");
            generate_default_candidates(active_dim, alpha)
        }
    };

    replace_v_candidates(state, cands);

    let v0 = get_v_candidates(state)
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            let mut v = vec![alpha];
            v.extend(uniform_vec(active_dim));
            v
        });

    if get_current_weight_vec(state).is_empty() {
        set_current_weight_vec(state, v0);
    }

    Ok(())
}

pub fn combine_feature_matrix_to_weights(
    map: &HashMap<String, Vec<f64>>,
    v_in: &[f64],
    active_feature_names: &[String],
) -> Vec<f64> {
    let d = active_feature_names.len();
    if d == 0 {
        return Vec::new();
    }
    let inv_sqrt_d = 1.0f64 / (d as f64).sqrt();

    // Normalize the input weight vector
    let mut v = vec![0.0; d];
    let n = d.min(v_in.len());
    v[..n].copy_from_slice(&v_in[..n]);
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for w in v.iter_mut() {
            *w /= norm;
        }
    } else {
        v = uniform_vec(d);
    }

    let expected_len = map
        .get(&active_feature_names[0])
        .map(|a| a.len())
        .unwrap_or(0);

    let mut out = Vec::with_capacity(expected_len);
    for i in 0..expected_len {
        let mut z = vec![0.0f64; d];
        for (j, name) in active_feature_names.iter().enumerate() {
            if let Some(arr) = map.get(name) {
                z[j] = arr.get(i).copied().unwrap_or(0.0);
            }
        }
        let mag = z.iter().map(|x| x * x).sum::<f64>().sqrt();
        let dot = z.iter().zip(v.iter()).map(|(a, b)| a * b).sum::<f64>();
        let w = (dot * inv_sqrt_d) * mag;
        out.push(w);
    }
    out
}

/// Filter a full canonicalized feature map to contain only active features.
fn filter_active_features(
    full_map: &HashMap<String, Vec<f64>>,
    active_feature_names: &[String],
) -> HashMap<String, Vec<f64>> {
    let mut active_map = HashMap::new();
    for name in active_feature_names {
        if let Some(arr) = full_map.get(name) {
            active_map.insert(name.clone(), arr.clone());
        }
    }
    active_map
}

pub fn load_and_align_features_map<S: HasMetadata>(
    state: &mut S,
    canonical_map: &HashMap<String, Vec<f64>>,
    sites: usize,
    active_dim: usize,
    active_feature_names: &[String],
    features_map_path: &Path,
) -> Result<(Vec<f64>, HashMap<String, Vec<f64>>), String> {
    ensure_v_candidates_for(state, features_map_path, active_dim)?;

    let v0_active: Vec<f64> = get_v_candidates(state)
        .first()
        .map(|v| v[1..].to_vec())
        .unwrap_or_else(|| uniform_vec(active_dim));

    // Build active-only map from canonicalized full map
    let active_map = filter_active_features(canonical_map, active_feature_names);

    let feats = combine_feature_matrix_to_weights(&active_map, &v0_active, active_feature_names);

    set_tpe_satisfied(state, true);
    let alpha = get_factor_params(state).alpha;
    let mut v_full = Vec::with_capacity(1 + v0_active.len());
    v_full.push(alpha.clamp(0.0, 1.0));
    v_full.extend_from_slice(&v0_active);
    set_current_weight_vec(state, v_full);

    // Resize feats to match sites
    let mut aligned = feats;
    aligned.resize(sites, 0.0);
    aligned.truncate(sites);

    Ok((aligned, active_map))
}

/// Apply a weight vector to recompute the features map. Strict validation:
/// rejects wrong length, non-finite values, and zero-norm weights.
pub fn apply_v_to_features<S: HasMetadata>(state: &mut S, v: &[f64]) -> Result<(), Error> {
    let active_dim = get_active_dim(state);
    let active_names = get_active_feature_names(state);

    if v.len() != active_dim {
        return Err(Error::illegal_argument(format!(
            "BOFuzz vector error: weight length {} != active_dim {}",
            v.len(),
            active_dim
        )));
    }

    if v.iter().any(|x| !x.is_finite()) {
        return Err(Error::illegal_argument(
            "BOFuzz vector error: non-finite active weight".to_string(),
        ));
    }

    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm <= 0.0 {
        return Err(Error::illegal_argument(
            "BOFuzz vector error: active weights have zero norm".to_string(),
        ));
    }

    // Normalize weights
    let mut normalized = v.to_vec();
    let inv = 1.0 / norm;
    for w in normalized.iter_mut() {
        *w *= inv;
    }

    let (feats, sites) = match state.metadata_map().get::<FeaturesMatrixMeta>() {
        Some(m) => {
            let feats = combine_feature_matrix_to_weights(&m.matrix, &normalized, &active_names);
            (feats, m.sites)
        }
        None => {
            let feats = state
                .metadata_map()
                .get::<FeaturesMapMeta>()
                .map(|m| m.feats.clone())
                .unwrap_or_default();
            let sites = feats.len();
            (feats, sites)
        }
    };

    let mut aligned = feats;
    aligned.resize(sites, 0.0);
    aligned.truncate(sites);

    if state.metadata_map().get::<FeaturesMapMeta>().is_some() {
        let m = state
            .metadata_map_mut()
            .get_mut::<FeaturesMapMeta>()
            .unwrap();
        m.feats = aligned;
    } else {
        state.add_metadata(FeaturesMapMeta { feats: aligned });
    }

    let alpha = get_factor_params(state).alpha;
    let mut v_full = Vec::with_capacity(1 + v.len());
    v_full.push(alpha.clamp(0.0, 1.0));
    v_full.extend(v);
    set_current_weight_vec(state, v_full);

    Ok(())
}
