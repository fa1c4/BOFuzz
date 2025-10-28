// feature_sched/tpe.rs
use std::time::{Duration, Instant};
use std::sync::RwLock;
use libafl_bolts::{rands::{StdRand, Rand}, current_time};
use core::num::NonZeroUsize;
use libafl::common::HasMetadata;
use crate::feature_sched::TpeHistoryMeta;
use crate::feature_sched::{get_v_candidates, push_v_candidate, vecn_eq, replace_v_candidates};

use libafl::observers::MapObserver;
use libafl_bolts::tuples::Handle;
use libafl::observers::HitcountsMapObserver;
use libafl::observers::map::StdMapObserver;

#[derive(Clone, Debug)]
pub struct TpeParams {
    pub gamma: f64,       // quantile threshold, like 0.2
    pub samples: usize,   // samples size of L, like 64
    pub bw: f64,          // KDE width like 0.15
    pub period: Duration, // window period like 60s
}

impl Default for TpeParams {
    fn default() -> Self {
        Self { gamma: 0.2, samples: 64, bw: 0.15, period: Duration::from_secs(60) }
    }
}

#[derive(Clone, Debug)]
pub struct Trial {
    pub vec: Vec<f64>,  // [alpha, v1..v8]
    pub reward: f64,
}

#[derive(Clone, Debug, Default)]
pub struct TpeState {
    pub trials: Vec<Trial>,
    pub last_vec: Vec<f64>,         // last applying vector
    pub window_start: Option<Instant>,
    pub last_corpus: Option<usize>, // last corpus.count of window
    pub last_cov: Option<usize>,    // last coverage edges of window
    pub no_new_counter: usize,      
    pub lock_best: bool,            // convergence flag
    pub best_fixed: Vec<f64>,       // best vec
    pub restored_once: bool,        // TpeStage entry restore once
}

fn now_epoch_ms() -> u64 {
    current_time().as_millis() as u64
}

fn rand_gaussian(rng: &mut StdRand) -> f64 {
    // Box-Muller: generate gaussian value mu as 0 and sigma as 1
    let u1 = (rng.next_float() as f64).clamp(f64::MIN_POSITIVE, 1.0);
    let u2 = rng.next_float() as f64;
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * core::f64::consts::PI * u2;
    r * theta.cos()
}

pub struct TpeOptimizer {
    pub params: TpeParams,
    pub state: RwLock<TpeState>,
}

impl TpeOptimizer {
    pub fn new(params: TpeParams) -> Self {
        Self { params, state: RwLock::new(TpeState::default()) }
    }

    pub fn restore_once<S: HasMetadata>(&self, state: &S) {
        let mut s = self.state.write().unwrap();
        if s.restored_once { return; }
        s.restored_once = true;

        if let Some(meta) = state.metadata_map().get::<TpeHistoryMeta>() {
            s.trials.clear();
            s.trials.reserve(meta.trials.len());
            for (v, r, _ts) in &meta.trials {
                s.trials.push(Trial { vec: v.clone(), reward: *r });
            }

            let max_trials = if meta.max_trials == 0 { 1024 } else { meta.max_trials };
            if s.trials.len() > max_trials {
                let drop_n = s.trials.len() - max_trials;
                s.trials.drain(0..drop_n);
            }

            s.last_vec = meta.last_vec.clone();
            s.last_corpus = None;
            s.last_cov = None;

            s.window_start = Some(Instant::now());
        }
    }

    pub fn window_due(&self) -> bool {
        let s = self.state.read().unwrap();
        match s.window_start {
            None => true,
            Some(t0) => t0.elapsed() >= self.params.period,
        }
    }

    pub fn advance_window(&self) {
        let mut s = self.state.write().unwrap();
        s.window_start = Some(Instant::now());
    }

    pub fn window_elapsed(&self) -> Duration {
        let s = self.state.read().unwrap();
        match s.window_start {
            None => Duration::ZERO,
            Some(t0) => t0.elapsed(),
        }
    }

    pub fn init_vec_if_empty(&self, v0: &[f64]) {
        let mut s = self.state.write().unwrap();
        if s.last_vec.is_empty() {
            s.last_vec = v0.to_vec();
        }
    }

    pub fn observe(&self, vec: &[f64], reward: f64) {
        let mut s = self.state.write().unwrap();
        s.trials.push(Trial { vec: vec.to_vec(), reward });

        const MAX_TRIALS: usize = 1024;
        if s.trials.len() > MAX_TRIALS {
            let drop_n = s.trials.len() - MAX_TRIALS;
            s.trials.drain(0..drop_n);
        }
    }

    fn gen_kde_candidates<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) -> usize {
        let (lset, gset, _y_star) = match self.split_l_g() {
            Some(x) => x,
            None => return 0,
        };

        let pool = get_v_candidates(state);
        let hist = {
            let s = self.state.read().unwrap();
            s.trials.iter().map(|t| t.vec.clone()).collect::<Vec<_>>()
        };

        let eps = 1e-6;
        let mut best: Option<(f64, Vec<f64>)> = None;

        for base_trial in &lset {
            let base = &base_trial.vec;
            let d = base.len();

            let mut cand = vec![0.0; d];
            for j in 0..d {
                let z = rand_gaussian(rng);                 // N(0,1)
                let mut v = base[j] + self.params.bw * z;   // width h = bw
                if v < 0.0 { v = -v; }                      // reflect [0,1]
                if v > 1.0 { v = 2.0 - v; }
                cand[j] = v.clamp(0.0, 1.0);
            }
            let cand = project_vec(cand);

            let dup_hist = hist.iter().any(|h| h.len() == cand.len() && vecn_eq(h, &cand, 1e-3));
            if dup_hist {
                continue;
            }
            let dup_pool = pool.iter().any(|p| p.len() == cand.len() && vecn_eq(p, &cand, 1e-3));
            if dup_pool {
                continue;
            }

            let l = kde_pdf_reflect(&lset, &cand, self.params.bw);
            let g = kde_pdf_reflect(&gset, &cand, self.params.bw);
            let score = if g > 0.0 { l / g } else { f64::INFINITY };
            if score <= 1.0 + eps {
                continue;
            }

            match best {
                None => best = Some((score, cand)),
                Some((best_s, _)) if score > best_s => best = Some((score, cand)),
                _ => {}
            }
        }

        if let Some((_score, chosen)) = best {
            push_v_candidate(state, chosen);
            1
        } else {
            0
        }
    }

    fn gen_kde_candidates_allin_L<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) -> usize {
        let (lset, gset, _y_star) = match self.split_l_g() {
            Some(x) => x,
            None => return 0, // history too few
        };

        let mut pool = get_v_candidates(state);
        let hist = {
            let s = self.state.read().unwrap();
            s.trials.iter().map(|t| t.vec.clone()).collect::<Vec<_>>()
        };

        let eps = 1e-6;
        let mut added = 0usize;
        for _ in 0..self.params.samples {
            let cand = project_vec(sample_from_kde_reflect(&lset, self.params.bw, rng));

            let l = kde_pdf_reflect(&lset, &cand, self.params.bw);
            let g = kde_pdf_reflect(&gset, &cand, self.params.bw);
            let score = if g > 0.0 { l / g } else { f64::INFINITY };

            if score <= 1.0 + eps {
                continue;
            }

            let dup_hist = hist.iter().any(|h| h.len() == cand.len() && vecn_eq(h, &cand, 1e-3));
            if dup_hist {
                continue;
            }

            let dup_pool = pool.iter().any(|p| p.len() == cand.len() && vecn_eq(p, &cand, 1e-3));
            if dup_pool {
                continue;
            }

            push_v_candidate(state, cand.clone());
            pool.push(cand);
            added += 1;
        }

        added
    }

    pub fn suggest<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) -> Vec<f64> {
        // 1) convergence: return best_v
        {
            let s = self.state.read().unwrap();
            if s.lock_best && !s.best_fixed.is_empty() {
                return s.best_fixed.clone();
            }
        }

        // 2) from Lset generate new vec with KDE sampling which reward_prediction >0
        let _added = self.gen_kde_candidates(state, rng);

        // 3) get next untried vec to apply 
        if let Some(v) = self.next_untried_from_pool(state) {
            return v;
        }

        // 4) queue is empty then no more vec satisfied reward > 0: set convergence then return best_v in history
        let best = self.best_by_lg()
            .or_else(|| {
                let s = self.state.read().unwrap();
                if s.last_vec.is_empty() { None } else { Some(s.last_vec.clone()) }
            })
            .unwrap_or_else(|| {
                vec![0.5; 9]
            });

        {
            let mut s = self.state.write().unwrap();
            s.best_fixed = best.clone();
            s.lock_best = true;
        }
        best
    }

    pub fn set_last_vec(&self, v: &[f64]) {
        let mut s = self.state.write().unwrap();
        s.last_vec = v.to_vec();
    }

    pub fn last_vec(&self) -> Vec<f64> {
        self.state.read().unwrap().last_vec.clone()
    }

    pub fn set_last_cov(&self, n: usize) {
        let mut s = self.state.write().unwrap();
        s.last_cov = Some(n);
    }
    pub fn take_reward_from_coverage(&self, cur_cov: usize) -> Option<f64> {
        let mut s = self.state.write().unwrap();
        let r = s.last_cov.map(|prev| (cur_cov as i64 - prev as i64) as f64);
        s.last_cov = Some(cur_cov);
        r
    }

    pub fn set_last_corpus(&self, n: usize) {
        let mut s = self.state.write().unwrap();
        s.last_corpus = Some(n);
    }

    pub fn take_reward_from_corpus(&self, cur_corpus: usize) -> Option<f64> {
        let mut s = self.state.write().unwrap();
        let r = s.last_corpus.map(|prev| (cur_corpus as i64 - prev as i64) as f64);
        s.last_corpus = Some(cur_corpus);
        r
    }

    pub fn persist_to_meta<S: HasMetadata>(&self, state: &mut S) {
        let s = self.state.read().unwrap();
        let meta = state.metadata_map_mut().get_or_insert_with::<TpeHistoryMeta>(Default::default);

        meta.trials.clear();
        meta.trials.reserve(s.trials.len());
        for t in &s.trials {
            meta.trials.push((t.vec.clone(), t.reward, now_epoch_ms()));
        }
        if meta.max_trials == 0 { meta.max_trials = 1024; }
        if meta.trials.len() > meta.max_trials {
            let drop_n = meta.trials.len() - meta.max_trials;
            meta.trials.drain(0..drop_n);
        }
        meta.last_vec = s.last_vec.clone();
        meta.last_corpus = s.last_corpus;
        meta.last_cov = s.last_cov;
        meta.last_check_ms = Some(now_epoch_ms());
    }

    // traverse all init candidates weight_vec
    pub fn next_untried_from_pool<S: HasMetadata>(&self, state: &mut S) -> Option<Vec<f64>> {
        let hist = {
            let s = self.state.read().unwrap();
            s.trials.iter().map(|t| &t.vec).cloned().collect::<Vec<_>>()
        };
        let mut pool = get_v_candidates(state);

        while let Some(front) = pool.first() {
            let seen = hist.iter().any(|h| h.len() == front.len() && vecn_eq(h, front, 1e-3));
            if seen {
                pool.remove(0);
            } else {
                break;
            }
        }
      
        let out = if pool.is_empty() {
            None
        } else {
            Some(project_vec(pool.remove(0)))
        };
        replace_v_candidates(state, pool);

        out
    }

    // calculate L/G sets and threshold according to trials, empty then return None
    pub fn split_l_g<'a>(&'a self) -> Option<(Vec<Trial>, Vec<Trial>, f64)> {
        let s = self.state.read().unwrap();
        if s.trials.len() < 5 { return None; }

        let mut trials = s.trials.clone();
        drop(s);

        trials.sort_by(|a, b| a.reward.partial_cmp(&b.reward).unwrap());
        let n = trials.len();
        let k = ((n as f64 * self.params.gamma).ceil() as usize).clamp(1, n);
        let y_star = trials[n - k].reward;

        let mut lset = Vec::new();
        let mut gset = Vec::new();
        for t in trials.into_iter() {
            if t.reward >= y_star { lset.push(t); } else { gset.push(t); }
        }
        if lset.is_empty() || gset.is_empty() { return None; }
        Some((lset, gset, y_star))
    }

    // calculate v's l/g
    pub fn l_over_g(&self, v: &[f64]) -> Option<f64> {
        let (lset, gset, _) = self.split_l_g()?;
        let l = kde_pdf_reflect(&lset, v, self.params.bw);
        let g = kde_pdf_reflect(&gset, v, self.params.bw);
        if g > 0.0 { Some(l / g) } else { Some(f64::INFINITY) }
    }

    // search for best v in history
    pub fn best_by_lg(&self) -> Option<Vec<f64>> {
        let (lset, gset, _) = self.split_l_g()?;
        let s = self.state.read().unwrap();
        let mut best: Option<(f64, Vec<f64>)> = None;
        for t in &s.trials {
            if t.vec.len() < 9 { continue; }
            let l = kde_pdf_reflect(&lset, &t.vec, self.params.bw);
            let g = kde_pdf_reflect(&gset, &t.vec, self.params.bw);
            let score = if g > 0.0 { l / g } else { f64::INFINITY };
            match best {
                None => best = Some((score, t.vec.clone())),
                Some((bs, _)) if score > bs => best = Some((score, t.vec.clone())),
                _ => {}
            }
        }
        best.map(|(_, v)| v)
    }
}

/* ---------------- KDE & sampler ---------------- */
fn gaussian_pdf(z: f64) -> f64 {
    const INV_SQRT_2PI: f64 = 0.398_942_280_401_432_7;
    INV_SQRT_2PI * (-0.5 * z * z).exp()
}

// for [0,1] reflection from boundary: x, -x, 2-x
fn reflect_pdf_1d(x: f64, mu: f64, h: f64) -> f64 {
    let z1 = (x - mu) / h;
    let z2 = (x + mu) / h;
    let z3 = (2.0 - (x + mu)) / h;
    (gaussian_pdf(z1) + gaussian_pdf(z2) + gaussian_pdf(z3)) / h
}

fn kde_pdf_reflect(set: &[Trial], x: &[f64], h: f64) -> f64 {
    let d = x.len();
    let n = set.len() as f64;
    let mut s = 0.0;
    for t in set.iter() {
        let mut p = 1.0;
        for j in 0..d {
            p *= reflect_pdf_1d(x[j], t.vec[j], h);
        }
        s += p;
    }
    s / n
}

fn sample_from_kde_reflect(set: &[Trial], h: f64, rng: &mut StdRand) -> Vec<f64> {
    let d = set[0].vec.len();
    let base = set[rng.below(NonZeroUsize::new(set.len()).unwrap())].vec.clone();
    let mut out = vec![0.0; d];
    for j in 0..d {
        // Gause disturbance
        let z = rand_gaussian(rng); // Gauss Rand
        let mut v = base[j] + h * z;
        if v < 0.0 { v = -v; }
        if v > 1.0 { v = 2.0 - v; }
        v = v.clamp(0.0, 1.0);
        out[j] = v;
    }
    project_vec(out)
}

// uniform
fn project_vec(mut v: Vec<f64>) -> Vec<f64> {
    if v.is_empty() { return v; }
    // alpha is v[0]
    v[0] = v[0].clamp(0.0, 1.0);

    // left 8 dim uniform as L-2
    let d = v.len();
    if d > 1 {
        let mut norm2 = 0.0;
        for j in 1..d { norm2 += v[j] * v[j]; }
        if norm2 > 0.0 {
            let inv = 1.0 / norm2.sqrt();
            for j in 1..d { v[j] *= inv; }
        } else {
            let u = 1.0 / 8f64.sqrt();
            for j in 1..=8.min(d-1) { v[j] = u; }
        }
    }
    v
}

fn jitter_and_project(v: &[f64], rng: &mut StdRand) -> Vec<f64> {
    let mut out = v.to_vec();
    for x in &mut out {
        let delta = 0.05 * (rng.next_float() as f64 - 0.5) * 2.0; // [-0.05, 0.05]
        *x = (*x + delta).clamp(0.0, 1.0);
    }
    project_vec(out)
}
