use libafl_bolts::SerdeAny;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct PathWeightMeta {
    pub w: f64,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct GlobalStatsMeta {
    pub stats: super::stats::WeightStats,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FeaturesMapMeta {
    pub feats: Vec<f64>,
}

#[derive(Debug, Serialize, Deserialize, SerdeAny, Clone)]
pub struct SancovIndexesMetadata {
    pub list: Vec<usize>,
}
impl SancovIndexesMetadata {
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FeaturesMatrixMeta {
    pub matrix: std::collections::HashMap<String, Vec<f64>>,
    pub sites: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FeatureSchemaFile {
    pub schema_version: u64,
    pub features: Vec<FeatureSpec>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FeatureSpec {
    pub id: String,
    pub name: String,
    pub group: Option<String>,
    pub aliases: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FeatureGlobalsMeta {
    pub features_active: bool,
    pub feat_exists: bool,
    pub tpe_satisfied: bool,

    pub feat_val0: f64,
    pub explore_time_secs: u64,
    pub tpe_period_secs: u64,
    pub alpha_init: f64,

    pub factor_params: super::factor::FactorParams,
    pub current_v: Vec<f64>,
    pub v_candidates: Vec<Vec<f64>>,
    pub fuzz_start_epoch_ms: u64,

    pub schema_version: u64,
    pub schema_features: Vec<FeatureSpec>,
    pub vec_mask: Vec<bool>,
    pub active_features: Vec<FeatureSpec>,
    pub active_feature_names: Vec<String>,
    pub feature_dim: usize,
}

impl Default for FeatureGlobalsMeta {
    fn default() -> Self {
        Self {
            features_active: false,
            feat_exists: false,
            tpe_satisfied: false,
            feat_val0: 0.0,
            explore_time_secs: 43200,
            tpe_period_secs: 600,
            alpha_init: f64::NAN,
            factor_params: super::factor::FactorParams {
                alpha: 1.0,
                beta: 0.6,
                gmin: 0.0,
                gmax: 3.0,
                use_tanh: false,
            },
            current_v: Vec::new(),
            v_candidates: Vec::new(),
            fuzz_start_epoch_ms: 0,
            schema_version: 0,
            schema_features: Vec::new(),
            vec_mask: Vec::new(),
            active_features: Vec::new(),
            active_feature_names: Vec::new(),
            feature_dim: 0,
        }
    }
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct TpeHistoryMeta {
    pub trials: Vec<(Vec<f64>, f64, u64)>,
    pub last_vec: Vec<f64>,
    pub last_check_ms: Option<u64>,
    pub last_corpus: Option<usize>,
    pub last_cov: Option<usize>,
    pub max_trials: usize,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FactorParamsMeta {
    pub params: super::factor::FactorParams,
}
