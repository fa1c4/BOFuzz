/*
feature_sched/stats.rs: define WeightStats
*/
use serde::{Serialize, Deserialize};
use libafl_bolts::SerdeAny;

#[derive(Serialize, Deserialize, SerdeAny, Clone, Debug, Default)]
pub struct WeightStats {
    pub n: u64,
    pub mu: f64,
    pub m2: f64,
}
impl WeightStats {
    #[inline]
    pub fn update(&mut self, w: f64) {
        self.n += 1;
        let delta = w - self.mu;
        self.mu += delta / (self.n as f64);
        self.m2 += delta * (w - self.mu);
    }
    #[inline]
    pub fn sigma(&self) -> f64 {
        if self.n > 1 { (self.m2 / ((self.n - 1) as f64)).sqrt() } else { 1e-9 }
    }
}
