/*
feature_sched/mod.rs: export packages
*/
pub mod features_map;
pub mod stats;
pub mod metadata;
pub mod factor;
pub mod accounting_stage;
pub mod power_stage;

// re-export for convenience
pub use factor::{FactorParams, compute_factor};
pub use accounting_stage::FeaturesAccountingStage;
pub use metadata::{FeaturesMapMeta, GlobalStatsMeta, PathWeightMeta};
pub use power_stage::FeatureAwarePowerStage;

use std::sync::{OnceLock, atomic::{AtomicBool, Ordering}};

// features enable switch
pub static FEAT_ENABLED: AtomicBool = AtomicBool::new(false);
pub fn features_enabled() -> bool { FEAT_ENABLED.load(Ordering::Relaxed) }
pub fn set_features_enabled(v: bool) { FEAT_ENABLED.store(v, Ordering::Relaxed); }

// factor global params store and get
static FACTOR_PARAMS: OnceLock<FactorParams> = OnceLock::new();

// setting global params and only set at the starting
pub fn set_factor_params(p: FactorParams) {
    let _ = FACTOR_PARAMS.set(p);
}

// getting the params otherwise set the alpha as 0.0
pub fn get_factor_params() -> &'static FactorParams {
    static DEFAULT: FactorParams = FactorParams { alpha: 0.0, beta: 0.6, gmin: 0.5, gmax: 3.0, use_tanh: false };
    FACTOR_PARAMS.get().unwrap_or(&DEFAULT)
}
