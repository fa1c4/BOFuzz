/*
feature_sched/metadata.rs: define metadata structures
*/
use serde::{Serialize, Deserialize};
use libafl_bolts::SerdeAny;

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct PathWeightMeta { pub w: f64 }

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct GlobalStatsMeta { pub stats: super::stats::WeightStats }

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FeaturesMapMeta { pub feats: Vec<f64> }

#[derive(Debug, Serialize, Deserialize, SerdeAny, Clone)]
pub struct SancovIndexesMetadata {
    pub list: Vec<usize>,
}
impl SancovIndexesMetadata {
    pub fn new(list: Vec<usize>) -> Self { Self { list } }
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FeaturesMatrixMeta {
    pub matrix: std::collections::HashMap<String, Vec<f64>>,
    pub sites: usize,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct FeatureGlobalsMeta {
    pub features_active: bool,       // FEATURES_ACTIVE
    pub feat_exists: bool,           // FEAT_EXISTS
    pub tpe_satisfied: bool,         // TPE_SATISFIED

    pub feat_val0: f64,              // FEAT_VAL0
    pub explore_time_secs: u64,      // EXPLORE_TIME
    pub tpe_period_secs: u64,        // TPE_PERIOD
    pub alpha_init: f64,             // ALPHA_INIT

    // params and vector
    pub factor_params: super::factor::FactorParams,
    pub current_v: Vec<f64>,         // 9 dim vec: [alpha, w1..w8]
    pub v_candidates: Vec<Vec<f64>>, // 9 dim candidates
    pub fuzz_start_epoch_ms: u64,    // FUZZ_START: epoch ms
}

impl Default for FeatureGlobalsMeta {
    fn default() -> Self {
        Self {
            features_active: false,
            feat_exists: false,
            tpe_satisfied: false,
            feat_val0: 0.0,
            explore_time_secs: 12 * 60 * 60,
            tpe_period_secs: 10 * 60,
            alpha_init: f64::NAN,
            factor_params: super::factor::FactorParams {
                alpha: 1.0, beta: 0.6, gmin: 0.0, gmax: 3.0, use_tanh: false
            },
            current_v: Vec::new(),
            v_candidates: Vec::new(),
            fuzz_start_epoch_ms: 0,
        }
    }
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct TpeHistoryMeta {
    pub trials: Vec<(Vec<f64>, f64, u64)>, // (vec, reward, ts_millis)
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
