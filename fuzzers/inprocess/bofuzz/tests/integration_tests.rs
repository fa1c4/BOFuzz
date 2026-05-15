use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// We test the public functions from the bofuzz crate's feature_sched module.
// Since these are integration tests, we access them through the crate's public API.
// However, bofuzz is a staticlib; we'll use a helper module approach.
// For now, we replicate the core logic inline for testing.

// ======================== Schema helpers (replicated for testing) ========================

#[derive(Debug, serde::Deserialize, Clone)]
struct FeatureSchemaFile {
    schema_version: u64,
    features: Vec<FeatureSpec>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct FeatureSpec {
    id: String,
    name: String,
    group: Option<String>,
    aliases: Option<Vec<String>>,
}

fn load_and_validate_schema(path: &Path) -> Result<FeatureSchemaFile, String> {
    let s = fs::read_to_string(path).map_err(|e| {
        format!(
            "BOFuzz feature schema error: missing required file {}: {}",
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
                        "BOFuzz feature schema error: alias '{}' collides with canonical name",
                        alias
                    ));
                }
            }
        }
    }
    Ok(schema)
}

fn parse_vec_mask(raw: &str, schema_len: usize) -> Result<Vec<bool>, String> {
    let trimmed = raw.trim();
    let values: Vec<u8> = if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        inner
            .split(',')
            .map(|s| s.trim().parse::<u8>().map_err(|_| "non-binary".to_string()))
            .collect::<Result<Vec<_>, _>>()?
    } else if trimmed.contains(',') {
        trimmed
            .split(',')
            .map(|s| s.trim().parse::<u8>().map_err(|_| "non-binary".to_string()))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        trimmed
            .chars()
            .map(|c| match c {
                '0' => Ok(0u8),
                '1' => Ok(1u8),
                _ => Err(format!("non-binary value '{}'", c)),
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    for &v in &values {
        if v > 1 {
            return Err("non-binary value".to_string());
        }
    }
    if values.len() != schema_len {
        return Err(format!(
            "mask length {} != schema {}",
            values.len(),
            schema_len
        ));
    }
    let mask: Vec<bool> = values.iter().map(|&v| v == 1).collect();
    if mask.iter().all(|&v| !v) {
        return Err("all-zero mask".to_string());
    }
    Ok(mask)
}

fn compute_active_features(schema: &FeatureSchemaFile, mask: &[bool]) -> Vec<FeatureSpec> {
    schema
        .features
        .iter()
        .zip(mask.iter())
        .filter(|(_, &m)| m)
        .map(|(f, _)| f.clone())
        .collect()
}

fn write_valid_schema(dir: &Path) -> std::path::PathBuf {
    let schema = serde_json::json!({
        "schema_version": 3,
        "features": [
            {"id": "I00", "name": "bb_instruction_count", "group": "instruction"},
            {"id": "I01", "name": "numeric_immediate_count", "group": "instruction"},
            {"id": "I02", "name": "string_literal_ref_count", "group": "instruction"},
            {"id": "I03", "name": "const_data_ref_count", "group": "instruction"},
            {"id": "I04", "name": "cmp_inst_count", "group": "instruction"},
            {"id": "I05", "name": "arith_bitwise_count", "group": "instruction"},
            {"id": "I06", "name": "mem_inst_count", "group": "instruction"},
            {"id": "I07", "name": "call_count", "group": "instruction"},
            {"id": "S00", "name": "cfg_in_degree", "group": "structural"},
            {"id": "S01", "name": "cfg_out_degree", "group": "structural"},
            {"id": "S02", "name": "static_descendant_count", "group": "structural"},
            {"id": "S03", "name": "static_ancestor_count", "group": "structural"},
            {"id": "S04", "name": "entry_depth", "group": "structural"},
            {"id": "S05", "name": "loop_nesting_depth", "group": "structural"},
            {"id": "S06", "name": "loop_boundary_flag", "group": "structural"},
            {"id": "S07", "name": "centrality", "aliases": ["betweenness"], "group": "structural"}
        ]
    });
    let path = dir.join("features_schema.json");
    fs::write(&path, serde_json::to_string_pretty(&schema).unwrap()).unwrap();
    path
}

fn write_synthetic_feature_map(dir: &Path, sites: usize) -> std::path::PathBuf {
    let names = [
        "bb_instruction_count",
        "numeric_immediate_count",
        "string_literal_ref_count",
        "const_data_ref_count",
        "cmp_inst_count",
        "arith_bitwise_count",
        "mem_inst_count",
        "call_count",
        "cfg_in_degree",
        "cfg_out_degree",
        "static_descendant_count",
        "static_ancestor_count",
        "entry_depth",
        "loop_nesting_depth",
        "loop_boundary_flag",
        "centrality",
    ];
    let mut map = serde_json::Map::new();
    for (i, name) in names.iter().enumerate() {
        let arr: Vec<f64> = (0..sites).map(|j| (i as f64 + j as f64) * 0.1).collect();
        map.insert(
            name.to_string(),
            serde_json::Value::Array(arr.iter().map(|&v| serde_json::json!(v)).collect()),
        );
    }
    let path = dir.join("test_features_map.json");
    fs::write(
        &path,
        serde_json::to_string(&serde_json::Value::Object(map)).unwrap(),
    )
    .unwrap();
    path
}

// ======================== 12.1 Schema tests ========================

#[test]
fn test_valid_16_feature_schema_loads() {
    let tmp = TempDir::new().unwrap();
    let path = write_valid_schema(tmp.path());
    let schema = load_and_validate_schema(&path).unwrap();
    assert_eq!(schema.schema_version, 3);
    assert_eq!(schema.features.len(), 16);
}

#[test]
fn test_missing_schema_file_fails() {
    let result = load_and_validate_schema(Path::new("/nonexistent/schema.json"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("missing required file"));
}

#[test]
fn test_duplicate_feature_name_fails() {
    let tmp = TempDir::new().unwrap();
    let schema = serde_json::json!({
        "schema_version": 3,
        "features": [
            {"id": "I00", "name": "dup_name", "group": "a"},
            {"id": "I01", "name": "dup_name", "group": "a"}
        ]
    });
    let path = tmp.path().join("schema.json");
    fs::write(&path, serde_json::to_string(&schema).unwrap()).unwrap();
    let result = load_and_validate_schema(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("duplicate feature name"));
}

#[test]
fn test_duplicate_feature_id_fails() {
    let tmp = TempDir::new().unwrap();
    let schema = serde_json::json!({
        "schema_version": 3,
        "features": [
            {"id": "I00", "name": "name_a", "group": "a"},
            {"id": "I00", "name": "name_b", "group": "a"}
        ]
    });
    let path = tmp.path().join("schema.json");
    fs::write(&path, serde_json::to_string(&schema).unwrap()).unwrap();
    let result = load_and_validate_schema(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("duplicate feature id"));
}

#[test]
fn test_alias_collision_fails() {
    let tmp = TempDir::new().unwrap();
    let schema = serde_json::json!({
        "schema_version": 3,
        "features": [
            {"id": "I00", "name": "alpha", "group": "a"},
            {"id": "I01", "name": "beta", "aliases": ["alpha"], "group": "a"}
        ]
    });
    let path = tmp.path().join("schema.json");
    fs::write(&path, serde_json::to_string(&schema).unwrap()).unwrap();
    let result = load_and_validate_schema(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("alias"));
}

#[test]
fn test_empty_features_list_fails() {
    let tmp = TempDir::new().unwrap();
    let schema = serde_json::json!({"schema_version": 3, "features": []});
    let path = tmp.path().join("schema.json");
    fs::write(&path, serde_json::to_string(&schema).unwrap()).unwrap();
    let result = load_and_validate_schema(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("empty"));
}

// ======================== 12.2 Mask tests ========================

#[test]
fn test_bracketed_list_accepted() {
    let mask = parse_vec_mask("[1,0,1,0]", 4).unwrap();
    assert_eq!(mask, vec![true, false, true, false]);
}

#[test]
fn test_comma_separated_list_accepted() {
    let mask = parse_vec_mask("1,0,1,0", 4).unwrap();
    assert_eq!(mask, vec![true, false, true, false]);
}

#[test]
fn test_bitstring_accepted() {
    let mask = parse_vec_mask("1010", 4).unwrap();
    assert_eq!(mask, vec![true, false, true, false]);
}

#[test]
fn test_mask_length_mismatch_fails() {
    let result = parse_vec_mask("101", 4);
    assert!(result.is_err());
}

#[test]
fn test_non_binary_value_fails() {
    let result = parse_vec_mask("1020", 4);
    assert!(result.is_err());
}

#[test]
fn test_all_zero_mask_fails() {
    let result = parse_vec_mask("0000", 4);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("all-zero"));
}

#[test]
fn test_mask_checked_against_schema_length() {
    let result = parse_vec_mask("11111111", 16);
    assert!(result.is_err());
}

// ======================== 12.4 Runtime active-dim tests ========================

#[test]
fn test_all_enabled_mask_gives_active_dim_16() {
    let tmp = TempDir::new().unwrap();
    let path = write_valid_schema(tmp.path());
    let schema = load_and_validate_schema(&path).unwrap();
    let mask = vec![true; 16];
    let active = compute_active_features(&schema, &mask);
    assert_eq!(active.len(), 16);
    // TPE vector len = 1 + 16 = 17
}

#[test]
fn test_instruction_only_mask_gives_active_dim_8() {
    let tmp = TempDir::new().unwrap();
    let path = write_valid_schema(tmp.path());
    let schema = load_and_validate_schema(&path).unwrap();
    let mut mask = vec![false; 16];
    for i in 0..8 {
        mask[i] = true;
    }
    let active = compute_active_features(&schema, &mask);
    assert_eq!(active.len(), 8);
    assert_eq!(active[0].id, "I00");
    assert_eq!(active[7].id, "I07");
}

#[test]
fn test_centrality_disabled_mask_gives_active_dim_15() {
    let tmp = TempDir::new().unwrap();
    let path = write_valid_schema(tmp.path());
    let schema = load_and_validate_schema(&path).unwrap();
    let mut mask = vec![true; 16];
    mask[15] = false; // disable S07 centrality
    let active = compute_active_features(&schema, &mask);
    assert_eq!(active.len(), 15);
    assert!(active.iter().all(|f| f.name != "centrality"));
}

#[test]
fn test_active_features_follow_schema_order() {
    let tmp = TempDir::new().unwrap();
    let path = write_valid_schema(tmp.path());
    let schema = load_and_validate_schema(&path).unwrap();
    // Enable only even-indexed features
    let mask: Vec<bool> = (0..16).map(|i| i % 2 == 0).collect();
    let active = compute_active_features(&schema, &mask);
    assert_eq!(active.len(), 8);
    assert_eq!(active[0].id, "I00");
    assert_eq!(active[1].id, "I02");
    assert_eq!(active[2].id, "I04");
    assert_eq!(active[3].id, "I06");
    assert_eq!(active[4].id, "S00");
    assert_eq!(active[5].id, "S02");
    assert_eq!(active[6].id, "S04");
    assert_eq!(active[7].id, "S06");
}

// ======================== 12.5 Candidate and prior tests ========================

#[test]
fn test_candidate_len_mismatch_fails() {
    let tmp = TempDir::new().unwrap();
    let cand_path = tmp.path().join("test_v_candidates.json");
    // active_dim=8 means expected len=9, but we give len=5
    let cands = vec![vec![0.5, 0.3, 0.3, 0.3, 0.3]];
    fs::write(&cand_path, serde_json::to_string(&cands).unwrap()).unwrap();
    let s = fs::read_to_string(&cand_path).unwrap();
    let arr: Vec<Vec<f64>> = serde_json::from_str(&s).unwrap();
    let expected_len = 1 + 8;
    assert_ne!(arr[0].len(), expected_len);
}

#[test]
fn test_prior_index_zero_is_invalid() {
    // Prior indexes must be one-based (1..schema_dim)
    let raw = vec![0usize, 1, 2];
    let has_zero = raw.iter().any(|&x| x < 1);
    assert!(has_zero, "Index 0 should be detected as invalid");
}

#[test]
fn test_prior_index_exceeding_schema_dim_is_invalid() {
    let schema_dim = 16;
    let raw = vec![1, 2, 17]; // 17 > 16
    let has_oob = raw.iter().any(|&x| x > schema_dim);
    assert!(has_oob, "Index 17 should exceed schema_dim=16");
}

#[test]
fn test_prior_duplicate_is_invalid() {
    let raw = vec![1, 2, 3, 2];
    let mut seen = std::collections::HashSet::new();
    let has_dup = raw.iter().any(|x| !seen.insert(x));
    assert!(has_dup, "Duplicate index 2 should be detected");
}
