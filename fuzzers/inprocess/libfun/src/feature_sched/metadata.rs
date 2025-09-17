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
