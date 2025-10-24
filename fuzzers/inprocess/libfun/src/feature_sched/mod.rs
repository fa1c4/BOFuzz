/*
feature_sched/mod.rs: export packages
*/
pub mod features_map;
pub mod stats;
pub mod metadata;
pub mod factor;
pub mod accounting_stage;
pub mod sancov_index_feedback;

// re-export for convenience
pub use factor::FactorParams;
pub use accounting_stage::FeaturesAccountingStage;
pub use metadata::{FeaturesMapMeta, SancovIndexesMetadata};
pub use sancov_index_feedback::SancovIndexFeedback;

use std::sync::{RwLock, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::Instant;

// set features active flag
pub static FEATURES_ACTIVE: AtomicBool = AtomicBool::new(false);
// features enable switch
pub static FEAT_ENABLED: AtomicBool = AtomicBool::new(false);
// whether features_map exists/loaded successfully
static FEAT_EXISTS: AtomicBool = AtomicBool::new(false);

// startup time record
pub static mut FUZZ_START: Option<Instant> = None;

// TPE weight vector candidates
pub use crate::feature_sched::features_map::{ V_CANDIDATES, CURRENT_V };
pub fn features_enabled() -> bool { FEAT_ENABLED.load(Ordering::Relaxed) }
pub fn set_features_enabled(v: bool) { FEAT_ENABLED.store(v, Ordering::Relaxed); }

pub fn feat_exists() -> bool { FEAT_EXISTS.load(Ordering::Relaxed) }
pub fn set_feat_exists(v: bool) { FEAT_EXISTS.store(v, Ordering::Relaxed); }

use libafl::schedulers::testcase_score::get_feat_mode;

static FEAT_VAL0: AtomicU64 = AtomicU64::new(0);

static ALPHA_INIT: AtomicU64 = AtomicU64::new(f64::NAN.to_bits());

// factor global params store and get
// Use RwLock to allow for mutable access to params
pub static FACTOR_PARAMS: RwLock<FactorParams> = RwLock::new(FactorParams { 
    alpha: 1.0, beta: 0.6, gmin: 0.0, gmax: 3.0, use_tanh: false 
});

// Function to set the factor parameters
pub fn set_factor_params(p: FactorParams) {
    let mut params = FACTOR_PARAMS.write().unwrap();
    *params = p;
}

// Function to get the factor parameters
pub fn get_factor_params() -> FactorParams {
    let params = FACTOR_PARAMS.read().unwrap();
    params.clone() // Clone to avoid borrowing issues
}

// Function to get current weight vector
pub fn get_current_weight_vec() -> Vec<f64> {
    CURRENT_V.read().unwrap().clone()
}

pub fn recompute_features_enabled() {
    let enabled = FEATURES_ACTIVE.load(Ordering::Relaxed)
        && FEAT_EXISTS.load(Ordering::Relaxed)
        && get_feat_mode() != 0;
    FEAT_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_feat0(v: f64) {
    FEAT_VAL0.store(v.to_bits(), Ordering::Relaxed);
}
pub fn get_feat0() -> f64 {
    f64::from_bits(FEAT_VAL0.load(Ordering::Relaxed))
}

pub fn set_alpha_init(v: f64) {
    ALPHA_INIT.store(v.to_bits(), Ordering::Relaxed);
}
pub fn get_alpha_init() -> f64 {
    f64::from_bits(ALPHA_INIT.load(Ordering::Relaxed))
}
