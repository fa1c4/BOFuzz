pub mod accounting_stage;
pub mod factor;
pub mod features_map;
pub mod metadata;
pub mod sancov_index_feedback;
pub mod stats;

pub use accounting_stage::FeaturesAccountingStage;
pub use factor::FactorParams;
pub use metadata::{FeatureSchemaFile, FeatureSpec, FeaturesMapMeta, SancovIndexesMetadata};
pub use sancov_index_feedback::SancovIndexFeedback;

use libafl_bolts::current_time;

pub mod tpe;
pub mod tpe_stage;
pub use tpe::{TpeOptimizer, TpeParams};
pub use tpe_stage::TpeStage;

pub use metadata::{FactorParamsMeta, FeatureGlobalsMeta, FeaturesMatrixMeta, TpeHistoryMeta};

use libafl::common::HasMetadata;
use libafl::schedulers::testcase_score::FeatModeMeta;

fn globals_mut<S: HasMetadata>(state: &mut S) -> &mut FeatureGlobalsMeta {
    state
        .metadata_map_mut()
        .get_or_insert_with::<FeatureGlobalsMeta>(Default::default)
}
fn globals<S: HasMetadata>(state: &S) -> FeatureGlobalsMeta {
    state
        .metadata_map()
        .get::<FeatureGlobalsMeta>()
        .cloned()
        .unwrap_or_default()
}

pub fn vecn_eq(a: &[f64], b: &[f64], eps: f64) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| (x - y).abs() <= eps)
}

// getters
pub fn get_features_active<S: HasMetadata>(state: &S) -> bool {
    globals(state).features_active
}
pub fn get_feat_exists<S: HasMetadata>(state: &S) -> bool {
    globals(state).feat_exists
}
pub fn get_tpe_satisfied<S: HasMetadata>(state: &S) -> bool {
    globals(state).tpe_satisfied
}
pub fn get_feat0<S: HasMetadata>(state: &S) -> f64 {
    globals(state).feat_val0
}
pub fn get_explore_time<S: HasMetadata>(state: &S) -> u64 {
    globals(state).explore_time_secs
}
pub fn get_tpe_period<S: HasMetadata>(state: &S) -> u64 {
    globals(state).tpe_period_secs
}
pub fn get_alpha_init<S: HasMetadata>(state: &S) -> f64 {
    globals(state).alpha_init
}
pub fn get_current_weight_vec<S: HasMetadata>(state: &S) -> Vec<f64> {
    globals(state).current_v.clone()
}
pub fn get_factor_params<S: HasMetadata>(state: &S) -> FactorParams {
    globals(state).factor_params.clone()
}
pub fn get_fuzz_start<S: HasMetadata>(state: &S) -> u64 {
    globals(state).fuzz_start_epoch_ms
}
pub fn get_active_dim<S: HasMetadata>(state: &S) -> usize {
    globals(state).feature_dim
}
pub fn get_active_feature_names<S: HasMetadata>(state: &S) -> Vec<String> {
    globals(state).active_feature_names.clone()
}
pub fn get_schema_features<S: HasMetadata>(state: &S) -> Vec<FeatureSpec> {
    globals(state).schema_features.clone()
}
pub fn get_active_features<S: HasMetadata>(state: &S) -> Vec<FeatureSpec> {
    globals(state).active_features.clone()
}
pub fn get_vec_mask<S: HasMetadata>(state: &S) -> Vec<bool> {
    globals(state).vec_mask.clone()
}

pub fn get_features_enabled<S: HasMetadata>(state: &S) -> bool {
    get_features_active(state) && get_feat_exists(state) && get_feat_mode(state) != 0
}

pub fn get_v_candidates<S: HasMetadata>(state: &mut S) -> Vec<Vec<f64>> {
    globals(state).v_candidates
}

pub fn get_feat_mode<S: HasMetadata>(state: &S) -> u8 {
    state
        .metadata_map()
        .get::<FeatModeMeta>()
        .map(|m| m.0)
        .unwrap_or(1)
}

// setters
pub fn set_features_active<S: HasMetadata>(state: &mut S, v: bool) {
    globals_mut(state).features_active = v;
}

pub fn set_feat_exists<S: HasMetadata>(state: &mut S, v: bool) {
    globals_mut(state).feat_exists = v;
}

pub fn set_tpe_satisfied<S: HasMetadata>(state: &mut S, v: bool) {
    globals_mut(state).tpe_satisfied = v;
}

pub fn set_feat0<S: HasMetadata>(state: &mut S, v: f64) {
    globals_mut(state).feat_val0 = v;
}

pub fn set_explore_time<S: HasMetadata>(state: &mut S, secs: u64) {
    globals_mut(state).explore_time_secs = secs;
}

pub fn set_tpe_period<S: HasMetadata>(state: &mut S, secs: u64) {
    globals_mut(state).tpe_period_secs = secs;
}

pub fn set_alpha_init<S: HasMetadata>(state: &mut S, v: f64) {
    globals_mut(state).alpha_init = v;
}

pub fn set_fuzz_start<S: HasMetadata>(state: &mut S) {
    globals_mut(state).fuzz_start_epoch_ms = current_time().as_millis() as u64;
}

pub fn set_factor_params<S: HasMetadata>(state: &mut S, p: FactorParams) {
    globals_mut(state).factor_params = p.clone();
}

pub fn set_schema_info<S: HasMetadata>(
    state: &mut S,
    schema_version: u64,
    schema_features: Vec<FeatureSpec>,
    vec_mask: Vec<bool>,
    active_features: Vec<FeatureSpec>,
) {
    let g = globals_mut(state);
    g.schema_version = schema_version;
    g.schema_features = schema_features;
    g.active_feature_names = active_features.iter().map(|f| f.name.clone()).collect();
    g.feature_dim = active_features.len();
    g.vec_mask = vec_mask;
    g.active_features = active_features;
}

pub fn push_v_candidate<S: HasMetadata>(state: &mut S, v: Vec<f64>) {
    let g = globals_mut(state);
    if !g.v_candidates.iter().any(|u| vecn_eq(u, &v, 1e-3)) {
        g.v_candidates.push(v);
    }
}
pub fn replace_v_candidates<S: HasMetadata>(state: &mut S, v: Vec<Vec<f64>>) {
    globals_mut(state).v_candidates = v;
}

pub fn set_current_weight_vec<S: HasMetadata>(state: &mut S, v: Vec<f64>) {
    globals_mut(state).current_v = v;
}

pub fn set_feat_mode<S: HasMetadata>(state: &mut S, m: u8) {
    let m = m.min(3);
    if let Some(meta) = state.metadata_map_mut().get_mut::<FeatModeMeta>() {
        meta.0 = m;
    } else {
        state.add_metadata(FeatModeMeta(m));
    }
}
