// feature_sched/tpe.rs
use std::time::{Duration, Instant};
use std::sync::RwLock;
use libafl_bolts::{rands::{StdRand, Rand}, current_time};
use core::num::NonZeroUsize;
use libafl::common::HasMetadata;
use crate::feature_sched::TpeHistoryMeta;
use crate::feature_sched::{get_v_candidates, push_v_candidate, vecn_eq};

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
    pub last_check: Option<Instant>,
    pub last_corpus: Option<usize>, // last corpus.count of window
    pub no_new_counter: usize,      
    pub lock_best: bool,            // convergence flag
    pub best_fixed: Vec<f64>,       // best vec
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

    pub fn init_vec_if_empty(&self, v0: &[f64]) {
        let mut s = self.state.write().unwrap();
        if s.last_vec.is_empty() {
            s.last_vec = v0.to_vec();
            s.last_check = Some(Instant::now());
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

    pub fn suggest<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) -> Vec<f64> {
        // 1) if reached covergence then return best_v
        {
            let s = self.state.read().unwrap();
            if s.lock_best && !s.best_fixed.is_empty() {
                return s.best_fixed.clone();
            }
        }

        // 2) warmup: apply weight_vec in candidates without reward
        if let Some(v) = self.next_untried_from_pool(state) {
            return v;
        }

        // 3) TPE optimizing: fetch l/g best vec then KDE to get new vec
        let added = self.refine_best_to_candidates(state, rng, 4);
        if added > 0 {
            if let Some(v) = self.next_untried_from_pool(state) {
                return v;
            }
        }

        // 4) no new candidates up to 3 times, then lock best in history 
        {
            let mut s = self.state.write().unwrap();
            if added == 0 {
                s.no_new_counter += 1;
                if s.no_new_counter >= 3 {
                    if let Some(best) = self.best_by_lg() {
                        s.best_fixed = best.clone();
                        s.lock_best = true;
                        s.no_new_counter = 0;
                        return s.best_fixed.clone();
                    }
                }
            } else {
                s.no_new_counter = 0;
            }
        }

        // 5) if samples are too few, use disturbance to generate new vecs; 
        let s = self.state.read().unwrap();
        if s.trials.len() < 5 {
            return jitter_and_project(&s.last_vec, rng);
        }
        drop(s);

        // 6) otherwise sampling as KDE
        let (lset, gset, _y_star) = match self.split_l_g() {
            Some(x) => x,
            None => {
                let s = self.state.read().unwrap();
                return jitter_and_project(&s.last_vec, rng);
            }
        };

        let mut best = None;
        for _ in 0..self.params.samples {
            let cand = sample_from_kde_reflect(&lset, self.params.bw, rng);
            let l = kde_pdf_reflect(&lset, &cand, self.params.bw);
            let g = kde_pdf_reflect(&gset, &cand, self.params.bw);
            let score = if g > 0.0 { l / g } else { f64::INFINITY };
            match best {
                None => best = Some((score, cand)),
                Some((bs, _)) if score > bs => best = Some((score, cand)),
                _ => {}
            }
        }
        best.map(|(_, v)| project_vec(v))
            .unwrap_or_else(|| {
                let s = self.state.read().unwrap();
                jitter_and_project(&s.last_vec, rng)
            })
    }

    // tpe window is over
    pub fn should_tick(&self) -> bool {
        let s = self.state.read().unwrap();
        match s.last_check {
            None => true,
            Some(t) => t.elapsed() >= self.params.period,
        }
    }

    // mark as tick
    pub fn mark_tick(&self) {
        let mut s = self.state.write().unwrap();
        s.last_check = Some(Instant::now());
    }

    pub fn set_last_vec(&self, v: &[f64]) {
        let mut s = self.state.write().unwrap();
        s.last_vec = v.to_vec();
    }

    pub fn last_vec(&self) -> Vec<f64> {
        self.state.read().unwrap().last_vec.clone()
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
        meta.last_check_ms = Some(now_epoch_ms());
    }

    pub fn restore_from_meta<S: HasMetadata>(&self, state: &S) {
        if let Some(meta) = state.metadata_map().get::<TpeHistoryMeta>() {
            let mut s = self.state.write().unwrap();
            s.trials.clear();
            s.trials.reserve(meta.trials.len());
            for (v, r, _ts) in &meta.trials {
                s.trials.push(Trial { vec: v.clone(), reward: *r });
            }
            s.last_vec = meta.last_vec.clone();
            s.last_corpus = meta.last_corpus;
            s.last_check = meta.last_check_ms.map(|_| Instant::now());
        }
    }

    // traverse all init candidates weight_vec
    pub fn next_untried_from_pool<S: HasMetadata>(&self, state: &S) -> Option<Vec<f64>> {
        let pool = get_v_candidates(state);
        let s = self.state.read().unwrap();
        'outer: for v9 in pool.iter() {
            for t in &s.trials {
                // same vec in history then continue
                if t.vec.len() == v9.len() && vecn_eq(&t.vec, v9, 1e-3) {
                    continue 'outer;
                }
            }
            return Some(project_vec(v9.clone()));
        }
        None
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

    // KDE sample from best vec, then put new vecs into V_CANDIDATES (not redundant), return number of new vecs
    pub fn refine_best_to_candidates<S: HasMetadata>(
        &self, state: &mut S, rng: &mut StdRand, k: usize
    ) -> usize {
        let (lset, _gset, _) = match self.split_l_g() { Some(x) => x, None => return 0 };
        let mut added = 0usize;
        for _ in 0..k {
            let cand = project_vec(sample_from_kde_reflect(&lset, self.params.bw, rng));
            push_v_candidate(state, cand);
            added += 1;
        }
        added
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
