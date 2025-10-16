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

use std::sync::{RwLock, atomic::{AtomicBool, Ordering}};
use std::time::Instant;
use std::sync::Arc;

// set features active flag
pub static FEATURES_ACTIVE: AtomicBool = AtomicBool::new(false);
// features enable switch
pub static FEAT_ENABLED: AtomicBool = AtomicBool::new(false);

// startup time record
pub static mut FUZZ_START: Option<Instant> = None;

pub fn features_enabled() -> bool { FEAT_ENABLED.load(Ordering::Relaxed) }
pub fn set_features_enabled(v: bool) { FEAT_ENABLED.store(v, Ordering::Relaxed); }

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
