use core::fmt::Write as _;
use core::num::NonZeroUsize;
use std::sync::RwLock;
use std::time::Duration;

use libafl::common::HasMetadata;
use libafl_bolts::{
    current_time,
    rands::{Rand, StdRand},
};

use crate::feature_sched::features_map::{normalize_simplex_eps, EPS};
use crate::feature_sched::{
    get_active_dim, get_v_candidates, push_v_candidate, replace_v_candidates, vecn_eq,
    ExploreCreditMeta, TpeHistoryMeta,
};

const MAX_TRIALS: usize = 1024;
pub const INVERSE_LAMBDA: f64 = 0.5;

#[derive(Clone, Debug)]
pub struct TpeParams {
    pub gamma: f64,
    pub samples: usize,
    pub bw: f64,
    pub period: Duration,
    pub trials_threshold: usize,
    pub re_tpe_threshold: Duration,
}

impl Default for TpeParams {
    fn default() -> Self {
        Self {
            gamma: 0.15,
            samples: 16,
            bw: 0.05,
            period: Duration::from_secs(600),
            trials_threshold: 5,
            re_tpe_threshold: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TpeTrial {
    pub iteration: u64,
    pub vector: Vec<f64>,
    pub reward: f64,
    pub active_start_ms: u64,
    pub active_end_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TpeState {
    pub trials: Vec<TpeTrial>,
    pub last_vec: Vec<f64>,
    pub lock_best: bool,
    pub best_fixed: Vec<f64>,
    pub restored_once: bool,
}

fn now_epoch_ms() -> u64 {
    current_time().as_millis() as u64
}

fn rand_gaussian(rng: &mut StdRand) -> f64 {
    let u1 = (rng.next_float() as f64).clamp(f64::MIN_POSITIVE, 1.0);
    let u2 = rng.next_float() as f64;
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * core::f64::consts::PI * u2;
    r * theta.cos()
}

pub fn centered_logit(simplex_v: &[f64]) -> Vec<f64> {
    let logs = simplex_v
        .iter()
        .map(|&w| (w.max(0.0) + EPS).ln())
        .collect::<Vec<_>>();
    let mean = logs.iter().copied().sum::<f64>() / logs.len().max(1) as f64;
    logs.into_iter().map(|z| z - mean).collect()
}

pub fn softmax(z: &[f64]) -> Vec<f64> {
    if z.is_empty() {
        return Vec::new();
    }
    let max_z = z.iter().copied().fold(f64::NEG_INFINITY, |a, b| a.max(b));
    let mut exps = z.iter().map(|v| (v - max_z).exp()).collect::<Vec<_>>();
    let sum = exps.iter().copied().sum::<f64>();
    if !sum.is_finite() || sum <= 0.0 {
        return vec![1.0 / z.len() as f64; z.len()];
    }
    for v in &mut exps {
        *v /= sum;
    }
    exps
}

pub fn logistic_normal_sample(center_simplex: &[f64], bw: f64, rng: &mut StdRand) -> Vec<f64> {
    let center = normalize_simplex_eps(center_simplex)
        .unwrap_or_else(|_| vec![1.0 / center_simplex.len().max(1) as f64; center_simplex.len()]);
    let mut z = centered_logit(&center);
    let h = bw.max(EPS);
    for v in &mut z {
        *v += h * rand_gaussian(rng);
    }
    let mean = z.iter().copied().sum::<f64>() / z.len().max(1) as f64;
    for v in &mut z {
        *v -= mean;
    }
    softmax(&z)
}

pub fn logistic_normal_log_pdf(x_simplex: &[f64], center_simplex: &[f64], bw: f64) -> f64 {
    if x_simplex.len() != center_simplex.len() || x_simplex.is_empty() {
        return f64::NEG_INFINITY;
    }
    let h = bw.max(EPS);
    let x = centered_logit(x_simplex);
    let c = centered_logit(center_simplex);
    let d = x.len() as f64;
    let sq = x
        .iter()
        .zip(c.iter())
        .map(|(a, b)| {
            let z = (a - b) / h;
            z * z
        })
        .sum::<f64>();
    -0.5 * sq - d * h.ln() - 0.5 * d * (2.0 * core::f64::consts::PI).ln()
}

pub fn kde_log_pdf(x_simplex: &[f64], centers: &[Vec<f64>], bw: f64) -> f64 {
    if centers.is_empty() {
        return f64::NEG_INFINITY;
    }
    let vals = centers
        .iter()
        .map(|c| logistic_normal_log_pdf(x_simplex, c, bw))
        .collect::<Vec<_>>();
    let max_v = vals
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, |a, b| a.max(b));
    if !max_v.is_finite() {
        return f64::NEG_INFINITY;
    }
    let sum = vals.iter().map(|v| (v - max_v).exp()).sum::<f64>();
    max_v + sum.ln() - (centers.len() as f64).ln()
}

pub fn sample_one_from_kde(centers: &[Vec<f64>], bw: f64, rng: &mut StdRand) -> Option<Vec<f64>> {
    if centers.is_empty() {
        return None;
    }
    let idx = rng.below(NonZeroUsize::new(centers.len()).unwrap());
    Some(logistic_normal_sample(&centers[idx], bw, rng))
}

pub fn inverse_simplex(best: &[f64]) -> Vec<f64> {
    let inv = best
        .iter()
        .map(|&w| 1.0 / (w.max(0.0) + EPS).powf(INVERSE_LAMBDA))
        .collect::<Vec<_>>();
    normalize_simplex_eps(&inv).unwrap_or_else(|_| vec![1.0 / best.len().max(1) as f64; best.len()])
}

pub struct TpeOptimizer {
    pub params: TpeParams,
    pub state: RwLock<TpeState>,
}

impl TpeOptimizer {
    pub fn new(params: TpeParams) -> Self {
        Self {
            params,
            state: RwLock::new(TpeState::default()),
        }
    }

    pub fn restore_once<S: HasMetadata>(&self, state: &S) {
        let mut s = self.state.write().unwrap();
        if s.restored_once {
            return;
        }
        s.restored_once = true;
        if let Some(meta) = state.metadata_map().get::<TpeHistoryMeta>() {
            s.trials.clear();
            for (i, (v, r, ts)) in meta.trials.iter().enumerate() {
                if let Ok(simplex) = normalize_simplex_eps(v) {
                    s.trials.push(TpeTrial {
                        iteration: i as u64,
                        vector: simplex,
                        reward: *r,
                        active_start_ms: *ts,
                        active_end_ms: *ts,
                    });
                }
            }
            s.last_vec = normalize_simplex_eps(&meta.last_vec).unwrap_or_default();
        }
    }

    pub fn set_last_vec(&self, v: &[f64]) {
        let mut s = self.state.write().unwrap();
        s.last_vec = normalize_simplex_eps(v).unwrap_or_else(|_| v.to_vec());
    }

    pub fn last_vec(&self) -> Vec<f64> {
        self.state.read().unwrap().last_vec.clone()
    }

    pub fn is_locked(&self) -> bool {
        self.state.read().unwrap().lock_best
    }

    pub fn lock_best(&self) {
        let best = self.best_by_reward().or_else(|| {
            let s = self.state.read().unwrap();
            if s.last_vec.is_empty() {
                None
            } else {
                Some(s.last_vec.clone())
            }
        });
        let mut s = self.state.write().unwrap();
        if let Some(best) = best {
            s.best_fixed = best;
        }
        s.lock_best = true;
    }

    pub fn unlock(&self) {
        self.state.write().unwrap().lock_best = false;
    }

    pub fn best_vec(&self) -> Option<Vec<f64>> {
        let s = self.state.read().unwrap();
        if !s.best_fixed.is_empty() {
            Some(s.best_fixed.clone())
        } else {
            drop(s);
            self.best_by_reward()
        }
    }

    pub fn observe_trial(
        &self,
        iteration: u64,
        vector: &[f64],
        reward: f64,
        active_start_ms: u64,
        active_end_ms: u64,
    ) {
        let Ok(vector) = normalize_simplex_eps(vector) else {
            return;
        };
        let mut s = self.state.write().unwrap();
        if let Some(last) = s.trials.last_mut() {
            if last.iteration == iteration || vecn_eq(&last.vector, &vector, 1e-6) {
                if reward > last.reward {
                    last.reward = reward;
                    last.active_end_ms = active_end_ms;
                }
                return;
            }
        }
        s.trials.push(TpeTrial {
            iteration,
            vector,
            reward,
            active_start_ms,
            active_end_ms,
        });
        if s.trials.len() > MAX_TRIALS {
            let drop_n = s.trials.len() - MAX_TRIALS;
            s.trials.drain(0..drop_n);
        }
    }

    pub fn enqueue_prior_candidates_from_credits<S: HasMetadata>(
        &self,
        state: &mut S,
        rng: &mut StdRand,
    ) {
        let active_dim = get_active_dim(state);
        if active_dim == 0 {
            return;
        }
        let credits = state
            .metadata_map()
            .get::<ExploreCreditMeta>()
            .map(|m| m.credits.clone())
            .unwrap_or_default();
        let positive = credits.iter().copied().filter(|v| *v > 0.0).sum::<f64>();
        let center = if credits.len() == active_dim && positive > EPS {
            normalize_simplex_eps(&credits)
                .unwrap_or_else(|_| vec![1.0 / active_dim as f64; active_dim])
        } else {
            eprintln!("BOFuzz warning: no positive explore credits collected; using equal feature distribution as KDE prior center");
            vec![1.0 / active_dim as f64; active_dim]
        };
        self.enqueue_samples_around(state, &center, self.params.samples, rng);
    }

    pub fn enqueue_samples_around<S: HasMetadata>(
        &self,
        state: &mut S,
        center: &[f64],
        count: usize,
        rng: &mut StdRand,
    ) {
        for _ in 0..count.max(1) {
            let cand = logistic_normal_sample(center, self.params.bw, rng);
            push_v_candidate(state, cand);
        }
    }

    pub fn enqueue_inverse_candidates<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) {
        if let Some(best) = self.best_vec() {
            let inv = inverse_simplex(&best);
            self.enqueue_samples_around(state, &inv, self.params.samples, rng);
            self.unlock();
        }
    }

    pub fn next_untried_from_pool<S: HasMetadata>(&self, state: &mut S) -> Option<Vec<f64>> {
        let hist = self
            .state
            .read()
            .unwrap()
            .trials
            .iter()
            .map(|t| t.vector.clone())
            .collect::<Vec<_>>();
        let mut pool = get_v_candidates(state);
        while let Some(front) = pool.first() {
            let seen = hist
                .iter()
                .any(|h| h.len() == front.len() && vecn_eq(h, front, 1e-3));
            if seen {
                pool.remove(0);
            } else {
                break;
            }
        }
        let out = if pool.is_empty() {
            None
        } else {
            let raw = pool.remove(0);
            normalize_simplex_eps(&raw).ok()
        };
        replace_v_candidates(state, pool);
        out
    }

    pub fn suggest_next<S: HasMetadata>(
        &self,
        state: &mut S,
        rng: &mut StdRand,
    ) -> Option<Vec<f64>> {
        if self.is_locked() {
            return None;
        }
        if let Some(v) = self.next_untried_from_pool(state) {
            return Some(v);
        }

        let (good, bad) = self.split_good_bad()?;
        let candidate = sample_one_from_kde(&good, self.params.bw, rng)?;
        let log_l = kde_log_pdf(&candidate, &good, self.params.bw);
        let log_g = kde_log_pdf(&candidate, &bad, self.params.bw);
        if log_l - log_g <= 0.0 {
            self.lock_best();
            return None;
        }
        Some(candidate)
    }

    fn split_good_bad(&self) -> Option<(Vec<Vec<f64>>, Vec<Vec<f64>>)> {
        let s = self.state.read().unwrap();
        let positive = s
            .trials
            .iter()
            .filter(|t| t.reward > 0.0)
            .cloned()
            .collect::<Vec<_>>();
        if positive.len() < self.params.trials_threshold {
            return None;
        }
        let mut positives = positive;
        positives.sort_by(|a, b| b.reward.partial_cmp(&a.reward).unwrap());
        let k = ((positives.len() as f64 * self.params.gamma).ceil() as usize)
            .clamp(1, positives.len());
        let good_ids = positives
            .iter()
            .take(k)
            .map(|t| t.iteration)
            .collect::<std::collections::HashSet<_>>();

        let mut good = Vec::new();
        let mut bad = Vec::new();
        for t in &s.trials {
            if t.reward > 0.0 && good_ids.contains(&t.iteration) {
                good.push(t.vector.clone());
            } else {
                bad.push(t.vector.clone());
            }
        }
        if good.is_empty() || bad.is_empty() {
            None
        } else {
            Some((good, bad))
        }
    }

    fn best_by_reward(&self) -> Option<Vec<f64>> {
        self.state
            .read()
            .unwrap()
            .trials
            .iter()
            .max_by(|a, b| a.reward.partial_cmp(&b.reward).unwrap())
            .map(|t| t.vector.clone())
    }

    pub fn persist_to_meta<S: HasMetadata>(&self, state: &mut S) {
        let s = self.state.read().unwrap();
        let meta = state
            .metadata_map_mut()
            .get_or_insert_with::<TpeHistoryMeta>(Default::default);
        meta.trials.clear();
        for t in &s.trials {
            meta.trials
                .push((t.vector.clone(), t.reward, t.active_end_ms));
        }
        meta.max_trials = MAX_TRIALS;
        meta.last_vec = s.last_vec.clone();
        meta.last_check_ms = Some(now_epoch_ms());
    }

    pub fn snapshot_trials_text(&self) -> String {
        let s = self.state.read().unwrap();
        let mut out = String::new();
        let _ = writeln!(&mut out, "[tpe-trials] count={}", s.trials.len());
        for (i, t) in s.trials.iter().enumerate() {
            let vv = t
                .vector
                .iter()
                .map(|x| format!("{:.4}", x))
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(
                &mut out,
                "[tpe-trial #{i}] iteration={} reward=ΔEdges={:.3} simplex=[{}] len={}",
                t.iteration,
                t.reward,
                vv,
                t.vector.len()
            );
        }
        out
    }
}
