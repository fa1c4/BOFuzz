/*
feature_sched/factor.rs: calculate the features factor
*/
use super::metadata::{GlobalStatsMeta, PathWeightMeta};
// use libafl::state::HasMetadata;
use libafl::common::HasMetadata; 
use crate::feature_sched::features_enabled;

#[derive(Clone, Debug)]
pub struct FactorParams {
    pub alpha: f64, // 0.0 ~ 0.6
    pub beta: f64,  // slope of exp/tanh: 0.4 ~ 0.8
    pub gmin: f64,  // 0.5
    pub gmax: f64,  // 3.0
    pub use_tanh: bool,
}

impl Default for FactorParams {
    fn default() -> Self {
        Self { alpha: 0.2, beta: 0.6, gmin: 0.5, gmax: 3.0, use_tanh: false }
    }
}

/// read testcase's PathWeight and global mean/variance, get the factor
pub fn compute_factor<S: HasMetadata>(params: &FactorParams, state: &S, entry: &impl HasMetadata) -> f64 {
    // disable features factor then return 1.0
    if !features_enabled() {
        return 1.0;
    }

    // lack meta data then do not statistic
    let Some(stats_meta) = state.metadata_map().get::<GlobalStatsMeta>() else { return 1.0; };
    let stats = stats_meta.stats.clone();
    let Some(pw) = entry.metadata_map().get::<PathWeightMeta>() else { return 1.0; };
    if stats.n < 2 {
        return 1.0; // paths count too few, do not statistic
    }

    let w = pw.w;
    let z = (w - stats.mu) / (stats.sigma() + 1e-9);

    let mut g = if params.use_tanh {
        1.0 + (params.beta * z).tanh()    // (0,2)
    } else {
        (params.beta * z).exp()           // (0, +inf)
    };
    if !g.is_finite() { g = 1.0; }
    g = g.clamp(params.gmin, params.gmax);

    // 1.0 + alpha*(g-1.0)
    1.0 + params.alpha * (g - 1.0)
}
