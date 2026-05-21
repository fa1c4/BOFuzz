use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread::JoinHandle;
use std::time::Duration;

use libafl::common::HasMetadata;
use libafl::corpus::Corpus;
use libafl::events::Event;
use libafl::feedbacks::MapFeedbackMetadata;
use libafl::monitors::{AggregatorOps, UserStats, UserStatsValue};
use libafl::schedulers::WeightedAliasTableDirtyMeta;
use libafl::HasNamedMetadata;
use libafl::{
    events::EventFirer, executors::Executor, executors::HasObservers, inputs::BytesInput,
    stages::Stage, state::HasCorpus, Error,
};
use libafl_bolts::current_time;
use libafl_bolts::rands::StdRand;

use super::features_map::apply_v_to_features;
use super::metadata::{
    FeaturesMapMeta, TpeIterationMeta, TpePhase, WeightComputeMode, WeightComputeModeMeta,
};
use super::tpe::{TpeOptimizer, TpeParams};
use super::weight_refresh::{
    build_corpus_weight_snapshot, publish_weight_recompute_result, spawn_weight_recompute_worker,
    WeightRecomputeResult,
};
use super::{
    get_active_dim, get_current_weight_vec, get_explore_time, get_feat_exists, get_feat_mode,
    get_fuzz_start, get_tpe_satisfied, get_v_candidates, set_features_active,
};
use crate::feature_sched::ExploreCreditMeta;

pub struct TpeStage {
    pub opt: TpeOptimizer,
    rng: StdRand,
    edges_name: String,
    pending_worker: Option<JoinHandle<()>>,
    result_rx: Option<Receiver<WeightRecomputeResult>>,
    pending_iteration: Option<u64>,
    last_explore_report_ms: u64,
}

impl TpeStage {
    pub fn new(params: TpeParams, edges_name: impl Into<String>) -> Self {
        Self {
            opt: TpeOptimizer::new(params),
            rng: StdRand::new(),
            edges_name: edges_name.into(),
            pending_worker: None,
            result_rx: None,
            pending_iteration: None,
            last_explore_report_ms: 0,
        }
    }

    fn now_ms() -> u64 {
        current_time().as_millis() as u64
    }

    fn current_edges<S: HasNamedMetadata>(&self, state: &S) -> u64 {
        state
            .named_metadata_map()
            .get::<MapFeedbackMetadata<u8>>(&self.edges_name)
            .map(|m| m.num_covered_map_indexes as u64)
            .unwrap_or(0)
    }

    fn explore_done<S: HasMetadata>(&self, state: &S) -> bool {
        let now_ms = Self::now_ms();
        let start_ms = get_fuzz_start(state);
        now_ms.saturating_sub(start_ms)
            >= Duration::from_secs(get_explore_time(state)).as_millis() as u64
    }

    fn phase<S: HasMetadata>(&self, state: &S) -> TpePhase {
        state
            .metadata_map()
            .get::<TpeIterationMeta>()
            .map(|m| m.phase)
            .unwrap_or(TpePhase::Explore)
    }

    fn set_phase<S: HasMetadata>(&self, state: &mut S, phase: TpePhase) {
        let meta = state
            .metadata_map_mut()
            .get_or_insert_with::<TpeIterationMeta>(Default::default);
        meta.phase = phase;
    }

    fn start_pending_recompute<S>(&mut self, state: &mut S, vector: Vec<f64>) -> Result<(), Error>
    where
        S: HasCorpus<BytesInput> + HasMetadata,
    {
        if self.pending_worker.is_some() {
            return Ok(());
        }
        let mode = state
            .metadata_map()
            .get::<WeightComputeModeMeta>()
            .map(|m| m.mode)
            .unwrap_or_default();
        if mode == WeightComputeMode::Frontier
            && state
                .metadata_map()
                .get::<super::metadata::SancovAcfgMeta>()
                .is_none()
        {
            return Err(Error::illegal_state(
                "frontier weight recompute requires SancovAcfgMeta".to_string(),
            ));
        }

        let next_iteration = state
            .metadata_map()
            .get::<TpeIterationMeta>()
            .map(|m| m.current_iteration.saturating_add(1))
            .unwrap_or(1);

        apply_v_to_features(state, &vector, next_iteration)?;
        self.opt.set_last_vec(&vector);

        let feature_weights = state
            .metadata_map()
            .get::<FeaturesMapMeta>()
            .map(|m| m.feats.clone())
            .unwrap_or_default();
        let snapshot = build_corpus_weight_snapshot(state, next_iteration, mode, feature_weights)?;
        let (handle, rx) = spawn_weight_recompute_worker(snapshot);
        self.pending_worker = Some(handle);
        self.result_rx = Some(rx);
        self.pending_iteration = Some(next_iteration);

        let meta = state
            .metadata_map_mut()
            .get_or_insert_with::<TpeIterationMeta>(Default::default);
        meta.current_iteration = next_iteration;
        meta.pending_iteration = Some(next_iteration);
        meta.phase = TpePhase::PendingRecompute;

        Ok(())
    }

    fn poll_pending<S>(&mut self, state: &mut S) -> Result<bool, Error>
    where
        S: HasCorpus<BytesInput> + HasMetadata + HasNamedMetadata,
    {
        let Some(rx) = &self.result_rx else {
            self.set_phase(state, TpePhase::ActiveWindow);
            return Ok(false);
        };
        match rx.try_recv() {
            Ok(result) => {
                if let Some(handle) = self.pending_worker.take() {
                    let _ = handle.join();
                }
                self.result_rx = None;
                self.pending_iteration = None;

                let current_iteration = state
                    .metadata_map()
                    .get::<TpeIterationMeta>()
                    .map(|m| m.current_iteration)
                    .unwrap_or(0);
                if result.iteration != current_iteration {
                    return Ok(false);
                }

                let iteration = result.iteration;
                publish_weight_recompute_result(state, result)?;
                state.add_metadata(WeightedAliasTableDirtyMeta {
                    iteration,
                    dirty: true,
                });
                set_features_active(state, true);

                let now = Self::now_ms();
                let edges = self.current_edges(state);
                let meta = state
                    .metadata_map_mut()
                    .get_or_insert_with::<TpeIterationMeta>(Default::default);
                meta.active_iteration = Some(iteration);
                meta.pending_iteration = None;
                meta.phase = TpePhase::ActiveWindow;
                meta.active_start_ms = Some(now);
                meta.active_start_edges = Some(edges);
                meta.last_new_edges_ms = Some(now);
                self.opt.persist_to_meta(state);
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => {
                if let Some(handle) = self.pending_worker.take() {
                    let _ = handle.join();
                }
                self.result_rx = None;
                self.pending_iteration = None;
                Err(Error::unknown(
                    "BOFuzz weight recompute worker disconnected".to_string(),
                ))
            }
        }
    }

    fn report<S, EM>(&mut self, state: &mut S, mgr: &mut EM, text: String) -> Result<(), Error>
    where
        S: HasCorpus<BytesInput>,
        EM: EventFirer<BytesInput, S>,
    {
        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: "tpe-info".into(),
                value: UserStats::new(UserStatsValue::String(text.into()), AggregatorOps::None),
                phantom: core::marker::PhantomData,
            },
        )
    }

    fn report_trials<S, EM>(&self, state: &mut S, mgr: &mut EM) -> Result<(), Error>
    where
        S: HasCorpus<BytesInput>,
        EM: EventFirer<BytesInput, S>,
    {
        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: "tpe-trials".into(),
                value: UserStats::new(
                    UserStatsValue::String(self.opt.snapshot_trials_text().into()),
                    AggregatorOps::None,
                ),
                phantom: core::marker::PhantomData,
            },
        )
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for TpeStage
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers,
    EM: EventFirer<BytesInput, S>,
    S: HasCorpus<BytesInput> + HasMetadata + HasNamedMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        mgr: &mut EM,
    ) -> Result<(), Error> {
        if !get_feat_exists(state) || get_feat_mode(state) == 0 || !get_tpe_satisfied(state) {
            return Ok(());
        }

        self.opt.restore_once(state);

        if self.phase(state) == TpePhase::PendingRecompute && self.pending_worker.is_none() {
            if get_current_weight_vec(state).is_empty() {
                self.set_phase(state, TpePhase::Explore);
            } else {
                self.set_phase(state, TpePhase::ActiveWindow);
            }
        }

        match self.phase(state) {
            TpePhase::Explore => {
                if !self.explore_done(state) {
                    let now = Self::now_ms();
                    if now.saturating_sub(self.last_explore_report_ms) > 30_000 {
                        self.last_explore_report_ms = now;
                        self.report(
                            state,
                            mgr,
                            "phase=Explore, msg=BOFuzz explore phase running; collecting frontier credits.".to_string(),
                        )?;
                    }
                    return Ok(());
                }

                if get_v_candidates(state).is_empty() {
                    self.opt
                        .enqueue_prior_candidates_from_credits(state, &mut self.rng);
                }
                let active_dim = get_active_dim(state);
                let candidate = self
                    .opt
                    .next_untried_from_pool(state)
                    .unwrap_or_else(|| vec![1.0 / active_dim.max(1) as f64; active_dim]);
                self.start_pending_recompute(state, candidate)?;
                self.report(
                    state,
                    mgr,
                    "phase=PendingRecompute, msg=started initial TPE weight recompute".to_string(),
                )?;
            }
            TpePhase::PendingRecompute => {
                let published = self.poll_pending(state)?;
                if published {
                    self.report(
                        state,
                        mgr,
                        "phase=ActiveWindow, msg=published feature weights and invalidated alias table".to_string(),
                    )?;
                }
                return Ok(());
            }
            TpePhase::ActiveWindow => {
                let now = Self::now_ms();
                let meta = state
                    .metadata_map()
                    .get::<TpeIterationMeta>()
                    .cloned()
                    .unwrap_or_default();
                let Some(start_ms) = meta.active_start_ms else {
                    return Ok(());
                };
                if now.saturating_sub(start_ms) < self.opt.params.period.as_millis() as u64 {
                    return Ok(());
                }

                let current_edges = self.current_edges(state);
                let start_edges = meta.active_start_edges.unwrap_or(current_edges);
                let reward = current_edges.saturating_sub(start_edges) as f64;
                let last_vec = get_current_weight_vec(state);
                if !last_vec.is_empty() {
                    self.opt.observe_trial(
                        meta.active_iteration.unwrap_or(meta.current_iteration),
                        &last_vec,
                        reward,
                        start_ms,
                        now,
                    );
                }

                if reward > 0.0 {
                    state
                        .metadata_map_mut()
                        .get_or_insert_with::<TpeIterationMeta>(Default::default)
                        .last_new_edges_ms = Some(now);
                }

                if let Some(next) = self.opt.suggest_next(state, &mut self.rng) {
                    self.start_pending_recompute(state, next)?;
                } else {
                    self.opt.lock_best();
                    self.set_phase(state, TpePhase::LockedBest);
                }
                self.opt.persist_to_meta(state);
                self.report_trials(state, mgr)?;

                let trials_len = self.opt.state.read().unwrap().trials.len();
                let simplex_sum = last_vec.iter().copied().sum::<f64>();
                let credits_sum = state
                    .metadata_map()
                    .get::<ExploreCreditMeta>()
                    .map(|m| m.credits.iter().copied().sum::<f64>())
                    .unwrap_or(0.0);
                self.report(
                    state,
                    mgr,
                    format!(
                        "phase={:?}, reward_edges={:.1}, edges={}, trials={}, corpus={}, active_dim={}, simplex_sum={:.6}, credits_sum={:.3}, bw={:.3}, gamma={:.3}, samples={}, pending_iteration={:?}, active_iteration={:?}",
                        self.phase(state),
                        reward,
                        current_edges,
                        trials_len,
                        state.corpus().count(),
                        get_active_dim(state),
                        simplex_sum,
                        credits_sum,
                        self.opt.params.bw,
                        self.opt.params.gamma,
                        self.opt.params.samples,
                        self.pending_iteration,
                        meta.active_iteration,
                    ),
                )?;
            }
            TpePhase::LockedBest => {
                let now = Self::now_ms();
                let current_edges = self.current_edges(state);
                let mut meta = state
                    .metadata_map()
                    .get::<TpeIterationMeta>()
                    .cloned()
                    .unwrap_or_default();
                let start_edges = meta.active_start_edges.unwrap_or(current_edges);
                if current_edges > start_edges {
                    meta.active_start_edges = Some(current_edges);
                    meta.last_new_edges_ms = Some(now);
                    state.add_metadata(meta);
                    return Ok(());
                }
                let last_new = meta.last_new_edges_ms.unwrap_or(now);
                if now.saturating_sub(last_new)
                    >= self.opt.params.re_tpe_threshold.as_millis() as u64
                {
                    self.opt.enqueue_inverse_candidates(state, &mut self.rng);
                    if let Some(next) = self.opt.next_untried_from_pool(state) {
                        self.start_pending_recompute(state, next)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        self.opt.restore_once(state);
        Ok(get_feat_exists(state) && get_feat_mode(state) != 0 && get_tpe_satisfied(state))
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
