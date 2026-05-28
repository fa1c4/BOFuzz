use crate::feature_sched::metadata::{
    FeatureSchemaFile, FeatureSpec, FeatureVectorMeta, FeaturesMapMeta, FeaturesMatrixMeta,
};
use crate::feature_sched::{
    get_active_dim, get_active_feature_names, get_v_candidates, replace_v_candidates,
    set_current_weight_vec, set_schema_info, set_tpe_satisfied,
};
use libafl::common::HasMetadata;
use libafl::Error;
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

pub const EPS: f64 = 1e-6;

const LEGACY_KEYS: &[&str] = &[
    "imme", "strc", "mem", "arith", "indeg", "offsp", "btw", "depth",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateFilePolicy {
    AllowExternalFile,
    IgnoreExternalFile,
}

#[derive(Clone, Debug, Default)]
pub struct CandidateFileStatus {
    pub path: Option<PathBuf>,
    pub loaded: bool,
}

pub struct FeatureMapLoadResult {
    pub feats: Vec<f64>,
    pub active_matrix: HashMap<String, Vec<f64>>,
    pub candidate_status: CandidateFileStatus,
}

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

    if schema.schema_version != 4 {
        return Err(format!(
            "BOFuzz feature schema error: schema_version must be 4, got {}",
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
            if v < 0.0 {
                return Err(format!(
                    "BOFuzz feature-map error: feature {} {} contains negative value at index {} under simplex mode",
                    spec.id, spec.name, i
                ));
            }
            if v > 1.0 + EPS {
                return Err(format!(
                    "BOFuzz feature-map error: feature {} {} value at index {} exceeds [0,1]",
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

pub fn equal_simplex(d: usize) -> Vec<f64> {
    if d == 0 {
        return Vec::new();
    }
    vec![1.0 / d as f64; d]
}

pub fn normalize_simplex_eps(v: &[f64]) -> Result<Vec<f64>, String> {
    if v.is_empty() {
        return Ok(Vec::new());
    }
    let mut sum = 0.0;
    let mut out = Vec::with_capacity(v.len());
    for &x in v {
        if !x.is_finite() {
            return Err("BOFuzz vector error: non-finite simplex weight".to_string());
        }
        if x < 0.0 {
            return Err("BOFuzz vector error: negative simplex weight".to_string());
        }
        let y = x + EPS;
        sum += y;
        out.push(y);
    }
    if !sum.is_finite() || sum <= EPS {
        return Err("BOFuzz vector error: simplex denominator is zero".to_string());
    }
    for x in &mut out {
        *x /= sum;
    }
    Ok(out)
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

fn candidate_format_error() -> String {
    "error: BOFuzz _v_candidates.json format changed.\nexpected weights-only vector length active_dim.\nold [alpha, weights...] format is no longer supported."
        .to_string()
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

    let mut out = Vec::with_capacity(arr.len());
    for (i, cand) in arr.iter().enumerate() {
        if cand.len() != active_dim {
            return Err(format!(
                "{} candidate {} length {} != active_dim {}",
                candidate_format_error(),
                i,
                cand.len(),
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
            if v < 0.0 {
                return Err(format!(
                    "BOFuzz candidate error: candidate {} contains negative value at index {}",
                    i, j
                ));
            }
        }
        out.push(normalize_simplex_eps(cand)?);
    }

    Ok(out)
}

/// Load user-provided candidate vectors according to the selected mask policy.
/// Candidate file absent -> empty pool. Candidate file present but invalid ->
/// fatal error only when external files are allowed by policy.
pub fn ensure_v_candidates_for<S: HasMetadata>(
    state: &mut S,
    features_map_path: &Path,
    active_dim: usize,
    policy: CandidateFilePolicy,
    mode_label: &str,
) -> Result<CandidateFileStatus, String> {
    let candidate_path = derive_dir_and_target(features_map_path)
        .map(|(dir, tgt)| dir.join(format!("{}_v_candidates.json", tgt)));

    if policy == CandidateFilePolicy::IgnoreExternalFile {
        eprintln!(
            "[BOFuzz candidate] mode={} policy=ignored reason=adaptive_mask_requires_credit_initialized_tpe",
            mode_label
        );
        return Ok(CandidateFileStatus {
            path: candidate_path,
            loaded: false,
        });
    }

    if !get_v_candidates(state).is_empty() {
        return Ok(CandidateFileStatus {
            path: candidate_path,
            loaded: false,
        });
    }

    let Some(cand_path) = candidate_path else {
        eprintln!(
            "[BOFuzz] Cannot derive v-candidates path; TPE will sample from explore credits."
        );
        replace_v_candidates(state, Vec::new());
        return Ok(CandidateFileStatus::default());
    };

    if cand_path.exists() {
        let file_cands = load_candidates_from(&cand_path, active_dim).map_err(|e| {
            format!(
                "BOFuzz candidate error: invalid {}: {}",
                cand_path.display(),
                e
            )
        })?;
        eprintln!(
            "[BOFuzz candidate] mode={} source=external-file priority=override-credit-init path={} active_dim={}",
            mode_label,
            cand_path.display(),
            active_dim
        );
        replace_v_candidates(state, file_cands);
        Ok(CandidateFileStatus {
            path: Some(cand_path),
            loaded: true,
        })
    } else {
        eprintln!(
            "[BOFuzz] No v-candidates file at {}; TPE will sample from explore credits.",
            cand_path.display()
        );
        replace_v_candidates(state, Vec::new());
        Ok(CandidateFileStatus {
            path: Some(cand_path),
            loaded: false,
        })
    }
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

    // BOFuzz externally uses a simplex vector. The historical dot/magnitude
    // formula expects a direction vector, so normalize internally only here.
    let mut v = vec![0.0; d];
    let n = d.min(v_in.len());
    v[..n].copy_from_slice(&v_in[..n]);
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for w in v.iter_mut() {
            *w /= norm;
        }
    } else {
        let u = 1.0f64 / (d as f64).sqrt();
        v = vec![u; d];
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
        out.push(if w.is_finite() { w.max(0.0) } else { 0.0 });
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

#[allow(clippy::too_many_arguments)]
pub fn load_and_align_features_map<S: HasMetadata>(
    state: &mut S,
    canonical_map: &HashMap<String, Vec<f64>>,
    sites: usize,
    active_dim: usize,
    active_feature_names: &[String],
    features_map_path: &Path,
    candidate_policy: CandidateFilePolicy,
    mode_label: &str,
) -> Result<FeatureMapLoadResult, String> {
    let candidate_status = ensure_v_candidates_for(
        state,
        features_map_path,
        active_dim,
        candidate_policy,
        mode_label,
    )?;

    let v0_active: Vec<f64> = get_v_candidates(state)
        .first()
        .cloned()
        .unwrap_or_else(|| equal_simplex(active_dim));

    let active_map = filter_active_features(canonical_map, active_feature_names);
    let feats = combine_feature_matrix_to_weights(&active_map, &v0_active, active_feature_names);

    set_tpe_satisfied(state, active_dim > 0);
    set_current_weight_vec(state, Vec::new());

    let mut aligned = feats;
    aligned.resize(sites, 0.0);
    aligned.truncate(sites);

    Ok(FeatureMapLoadResult {
        feats: aligned,
        active_matrix: active_map,
        candidate_status,
    })
}

pub fn install_committed_runtime_mask<S: HasMetadata>(
    state: &mut S,
    schema: &FeatureSchemaFile,
    mask: &[bool],
) -> Result<(), Error> {
    if mask.len() != schema.features.len() {
        return Err(Error::illegal_argument(format!(
            "BOFuzz mask error: committed mask length {} != schema_dim {}",
            mask.len(),
            schema.features.len()
        )));
    }
    if mask.iter().all(|enabled| !*enabled) {
        return Err(Error::illegal_argument(
            "BOFuzz mask error: committed mask disables every schema feature".to_string(),
        ));
    }

    let active_features = compute_active_features(schema, mask);
    let active_feature_names = active_features
        .iter()
        .map(|feature| feature.name.clone())
        .collect::<Vec<_>>();

    set_schema_info(
        state,
        schema.schema_version,
        schema.features.clone(),
        mask.to_vec(),
        active_features,
    );

    if let Some(matrix) = state.metadata_map_mut().get_mut::<FeaturesMatrixMeta>() {
        matrix.matrix = filter_active_features(&matrix.matrix, &active_feature_names);
    }

    replace_v_candidates(state, Vec::new());
    set_current_weight_vec(state, Vec::new());
    set_tpe_satisfied(state, !active_feature_names.is_empty());
    Ok(())
}

/// Apply a simplex feature-weight vector to recompute the scalar feature map.
pub fn apply_v_to_features<S: HasMetadata>(
    state: &mut S,
    simplex_v: &[f64],
    iteration: u64,
) -> Result<(), Error> {
    let active_dim = get_active_dim(state);
    let active_names = get_active_feature_names(state);

    if simplex_v.len() != active_dim {
        return Err(Error::illegal_argument(format!(
            "BOFuzz vector error: weight length {} != active_dim {}",
            simplex_v.len(),
            active_dim
        )));
    }

    let simplex_weights = normalize_simplex_eps(simplex_v).map_err(Error::illegal_argument)?;

    let (feats, sites) = match state.metadata_map().get::<FeaturesMatrixMeta>() {
        Some(m) => {
            let feats =
                combine_feature_matrix_to_weights(&m.matrix, &simplex_weights, &active_names);
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

    state.add_metadata(FeatureVectorMeta {
        iteration,
        simplex_weights: simplex_weights.clone(),
    });
    set_current_weight_vec(state, simplex_weights);

    Ok(())
}
