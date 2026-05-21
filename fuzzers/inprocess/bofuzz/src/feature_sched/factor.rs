/*
feature_sched/factor.rs: calculate the features factor
*/
use super::metadata::{
    GlobalStatsMeta, PathWeightMeta, TestcaseFeatureWeightMeta, WeightComputeMode,
    WeightComputeModeMeta,
};
use serde::{Deserialize, Serialize};
// use libafl::state::HasMetadata;
use crate::feature_sched::get_features_enabled;
use libafl::common::HasMetadata;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FactorParams {
    pub alpha: f64, // 0.0 ~ 1.0
    pub beta: f64,  // slope of exp/tanh: 0.4 ~ 0.8
    pub gmin: f64,  // 0.0
    pub gmax: f64,  // 3.0
    pub use_tanh: bool,
}

impl Default for FactorParams {
    fn default() -> Self {
        Self {
            alpha: 0.85,
            beta: 0.6,
            gmin: 0.5,
            gmax: 2.0,
            use_tanh: false,
        }
    }
}

/// read testcase's PathWeight and global mean/variance, get the factor
pub fn compute_factor<S: HasMetadata>(
    params: &FactorParams,
    state: &S,
    entry: &impl HasMetadata,
) -> f64 {
    // disable features factor then return 1.0
    if !get_features_enabled(state) {
        return 1.0;
    }

    // lack meta data then do not statistic
    let Some(stats_meta) = state.metadata_map().get::<GlobalStatsMeta>() else {
        return 1.0;
    };
    let stats = stats_meta.stats.clone();
    let mode = state
        .metadata_map()
        .get::<WeightComputeModeMeta>()
        .map(|m| m.mode)
        .unwrap_or_default();

    let w = match mode {
        WeightComputeMode::Frontier => entry
            .metadata_map()
            .get::<TestcaseFeatureWeightMeta>()
            .map(|m| m.weight),
        WeightComputeMode::Path => entry.metadata_map().get::<PathWeightMeta>().map(|m| m.w),
    };
    let Some(w) = w else {
        return 1.0;
    };
    if stats.n < 2 {
        return 1.0; // paths count too few, do not statistic
    }

    let z = (w - stats.mu) / (stats.sigma() + 1e-9);

    let raw_g = if params.use_tanh {
        1.0 + (params.beta * z).tanh()
    } else {
        (params.beta * z).exp()
    };
    let raw_g = if raw_g.is_finite() { raw_g } else { 1.0 };
    let blended = 1.0 + params.alpha * (raw_g - 1.0);
    blended.clamp(params.gmin, params.gmax)
}
