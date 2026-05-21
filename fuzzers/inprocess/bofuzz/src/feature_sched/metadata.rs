use libafl::corpus::CorpusId;
use libafl_bolts::SerdeAny;
use serde::{Deserialize, Serialize};

pub type BitSet = Vec<bool>;

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

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug)]
pub struct SancovAcfgMeta {
    pub iteration: u64,
    pub n_sancov_sites: usize,
    pub successors: Vec<Vec<usize>>,
    pub predecessors: Vec<Vec<usize>>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeightComputeMode {
    Frontier,
    Path,
}

impl Default for WeightComputeMode {
    fn default() -> Self {
        Self::Frontier
    }
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct WeightComputeModeMeta {
    pub mode: WeightComputeMode,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct TestcaseFeatureWeightMeta {
    pub iteration: u64,
    pub weight: f64,
    pub mode: WeightComputeMode,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct FrontierMeta {
    pub iteration: u64,
    pub covered: BitSet,
    pub f_prev: BitSet,
    pub f_next: BitSet,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct CoverageProgressMeta {
    pub last_covered_edges: u64,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct CoverageDeltaMeta {
    pub iteration: u64,
    pub delta_edges: u64,
    pub newly_covered_sancov: Vec<usize>,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct ExploreCreditMeta {
    pub iteration: u64,
    pub credits: Vec<f64>,
    pub total_delta_edges: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ExploreCreditEntry {
    pub iteration: u64,
    pub corpus_id: Option<CorpusId>,
    pub delta_edges: u64,
    pub frontier_nodes: Vec<usize>,
    pub credit_delta: Vec<f64>,
    pub cumulative_credits: Vec<f64>,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct ExploreCreditHistoryMeta {
    pub entries: Vec<ExploreCreditEntry>,
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct FeatureVectorMeta {
    pub iteration: u64,
    pub simplex_weights: Vec<f64>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpePhase {
    Explore,
    PendingRecompute,
    ActiveWindow,
    LockedBest,
}

impl Default for TpePhase {
    fn default() -> Self {
        Self::Explore
    }
}

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct TpeIterationMeta {
    pub current_iteration: u64,
    pub active_iteration: Option<u64>,
    pub pending_iteration: Option<u64>,
    pub phase: TpePhase,
    pub active_start_ms: Option<u64>,
    pub active_start_edges: Option<u64>,
    pub last_new_edges_ms: Option<u64>,
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
            alpha_init: 0.85,
            factor_params: super::factor::FactorParams::default(),
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
