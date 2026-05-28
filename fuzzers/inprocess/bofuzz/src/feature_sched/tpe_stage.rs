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

use super::features_map::{apply_v_to_features, install_committed_runtime_mask};
use super::mask_selection::{
    equal_simplex, mask_to_bitstring, normalize_credit_or_equal_simplex, project_vector_by_mask,
    select_positive_credit_top_k_mask,
};
use super::metadata::{
    FeatureSchemaFile, FeaturesMapMeta, TpeInitSource, TpeIterationMeta, TpePhase, VecMaskMode,
    VecMaskRuntimeMeta, WeightComputeMode, WeightComputeModeMeta,
};
use super::tpe::{TpeOptimizer, TpeParams};
use super::weight_refresh::{
    build_corpus_weight_snapshot, publish_weight_recompute_result, spawn_weight_recompute_worker,
    WeightRecomputeResult,
};
use super::{
    get_active_dim, get_active_feature_names, get_current_weight_vec, get_explore_time,
    get_feat_exists, get_feat_mode, get_fuzz_start, get_schema_features, get_schema_version,
    get_tpe_satisfied, get_v_candidates, get_vec_mask, replace_v_candidates, set_features_active,
    validate_committed_vector_dimensions,
};
use crate::feature_sched::runtime_data::maybe_export_runtime_data;
use crate::feature_sched::{ExploreCreditMeta, RuntimeCreditMeta};

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

    fn schema_from_state<S: HasMetadata>(state: &S) -> FeatureSchemaFile {
        FeatureSchemaFile {
            schema_version: get_schema_version(state),
            features: get_schema_features(state),
        }
    }

    fn credits_with_dim(credits: Vec<f64>, dim: usize, label: &str) -> Result<Vec<f64>, Error> {
        if credits.is_empty() {
            return Ok(vec![0.0; dim]);
        }
        if credits.len() != dim {
            return Err(Error::illegal_state(format!(
                "BOFuzz {} credit length {} != expected dimension {}",
                label,
                credits.len(),
                dim
            )));
        }
        Ok(credits)
    }

    fn positive_credit_stats(credits: &[f64]) -> (usize, f64) {
        let mut count = 0;
        let mut sum = 0.0;
        for &credit in credits {
            if credit > 0.0 {
                count += 1;
                sum += credit;
            }
        }
        (count, sum)
    }

    fn selected_names(schema: &FeatureSchemaFile, mask: &[bool]) -> Vec<String> {
        schema
            .features
            .iter()
            .zip(mask.iter())
            .filter(|(_, enabled)| **enabled)
            .map(|(feature, _)| feature.name.clone())
            .collect()
    }

    fn selected_indices(mask: &[bool]) -> Vec<usize> {
        mask.iter()
            .enumerate()
            .filter_map(|(idx, enabled)| enabled.then_some(idx))
            .collect()
    }

    fn set_runtime_meta<S: HasMetadata>(state: &mut S, runtime: VecMaskRuntimeMeta) {
        state.add_metadata(runtime);
    }

    fn commit_mask_and_tpe_initialization_before_first_tpe<S, EM>(
        &mut self,
        state: &mut S,
        _mgr: &mut EM,
    ) -> Result<(), Error>
    where
        S: HasMetadata,
    {
        let mut runtime = state
            .metadata_map()
            .get::<VecMaskRuntimeMeta>()
            .cloned()
            .unwrap_or_default();

        if runtime.tpe_init_committed {
            validate_committed_vector_dimensions(state)?;
            return Ok(());
        }

        let schema = Self::schema_from_state(state);
        let schema_dim = schema.features.len();
        let explore_credits_raw = state
            .metadata_map()
            .get::<ExploreCreditMeta>()
            .map(|meta| meta.credits.clone())
            .unwrap_or_default();

        match runtime.mode {
            VecMaskMode::Full => {
                let active_dim = get_active_dim(state);
                if active_dim != schema_dim {
                    return Err(Error::illegal_state(format!(
                        "BOFuzz full-mode error: active_dim {} != schema_dim {}",
                        active_dim, schema_dim
                    )));
                }
                let credits = Self::credits_with_dim(explore_credits_raw, active_dim, "full")?;
                let (normalized, has_positive, positive_sum) =
                    normalize_credit_or_equal_simplex(&credits).map_err(Error::illegal_state)?;
                let (positive_count, _) = Self::positive_credit_stats(&credits);

                runtime.mask_committed = true;
                runtime.tpe_init_committed = true;
                runtime.effective_mask = vec![true; schema_dim];
                runtime.selected_feature_names =
                    Self::selected_names(&schema, &runtime.effective_mask);
                runtime.selected_schema_indices = Self::selected_indices(&runtime.effective_mask);
                runtime.explore_credits_full = credits.clone();
                runtime.explore_credits_active = credits.clone();
                runtime.normalized_credit_init_v = normalized.clone();
                runtime.positive_credit_count = positive_count;
                runtime.positive_credit_sum = positive_sum;
                runtime.fallback_reason = None;
                runtime.tpe_init_source = if runtime.candidate_file_loaded {
                    Some(TpeInitSource::ExternalCandidateFile)
                } else if has_positive {
                    Some(TpeInitSource::ExploreCreditsExactFirst)
                } else {
                    Some(TpeInitSource::EqualSimplexFallback)
                };

                let source = runtime.tpe_init_source.clone();
                let candidate_loaded = runtime.candidate_file_loaded;
                Self::set_runtime_meta(state, runtime.clone());
                if !candidate_loaded {
                    replace_v_candidates(state, Vec::new());
                    self.opt.enqueue_exact_then_neighbor_candidates(
                        state,
                        &normalized,
                        &mut self.rng,
                    )?;
                }
                eprintln!(
                    "[BOFuzz mask] mode=full status=tpe-init source={:?} active_dim={} mask={} credits_active={:?} normalized_credit_init_v={:?}",
                    source,
                    active_dim,
                    mask_to_bitstring(&runtime.effective_mask),
                    credits,
                    normalized
                );
            }
            VecMaskMode::Explicit => {
                let requested = runtime.requested_explicit_mask.clone().ok_or_else(|| {
                    Error::illegal_state(
                        "BOFuzz explicit-mode error: missing persisted explicit mask".to_string(),
                    )
                })?;
                if get_vec_mask(state) != requested {
                    return Err(Error::illegal_state(
                        "BOFuzz resume error: explicit vec-mask differs from persisted committed mask"
                            .to_string(),
                    ));
                }
                let active_dim = get_active_dim(state);
                let credits = Self::credits_with_dim(explore_credits_raw, active_dim, "explicit")?;
                let (normalized, has_positive, positive_sum) =
                    normalize_credit_or_equal_simplex(&credits).map_err(Error::illegal_state)?;
                let (positive_count, _) = Self::positive_credit_stats(&credits);

                runtime.mask_committed = true;
                runtime.tpe_init_committed = true;
                runtime.effective_mask = requested;
                runtime.selected_feature_names = get_active_feature_names(state);
                runtime.selected_schema_indices = Self::selected_indices(&runtime.effective_mask);
                runtime.explore_credits_full = Vec::new();
                runtime.explore_credits_active = credits.clone();
                runtime.normalized_credit_init_v = normalized.clone();
                runtime.positive_credit_count = positive_count;
                runtime.positive_credit_sum = positive_sum;
                runtime.fallback_reason = None;
                runtime.tpe_init_source = if runtime.candidate_file_loaded {
                    Some(TpeInitSource::ExternalCandidateFile)
                } else if has_positive {
                    Some(TpeInitSource::ExploreCreditsExactFirst)
                } else {
                    Some(TpeInitSource::EqualSimplexFallback)
                };

                let source = runtime.tpe_init_source.clone();
                let candidate_loaded = runtime.candidate_file_loaded;
                Self::set_runtime_meta(state, runtime.clone());
                if !candidate_loaded {
                    replace_v_candidates(state, Vec::new());
                    self.opt.enqueue_exact_then_neighbor_candidates(
                        state,
                        &normalized,
                        &mut self.rng,
                    )?;
                }
                eprintln!(
                    "[BOFuzz mask] mode=explicit status=tpe-init source={:?} active_dim={} mask={} credits_active={:?} normalized_credit_init_v={:?}",
                    source,
                    active_dim,
                    mask_to_bitstring(&runtime.effective_mask),
                    credits,
                    normalized
                );
            }
            VecMaskMode::AutoCredit => {
                let credits =
                    Self::credits_with_dim(explore_credits_raw, schema_dim, "auto-credit")?;
                let (positive_count, positive_sum) = Self::positive_credit_stats(&credits);
                let selected_mask =
                    select_positive_credit_top_k_mask(&credits, schema_dim, runtime.credit_top_k)
                        .map_err(Error::illegal_state)?;

                let (effective_mask, active_credits, normalized, source, fallback_reason) =
                    if let Some(mask) = selected_mask {
                        install_committed_runtime_mask(state, &schema, &mask)?;
                        let active_credits = project_vector_by_mask(&credits, &mask)
                            .map_err(Error::illegal_state)?;
                        let (normalized, _, _) = normalize_credit_or_equal_simplex(&active_credits)
                            .map_err(Error::illegal_state)?;
                        (
                            mask,
                            active_credits,
                            normalized,
                            TpeInitSource::ExploreCreditsExactFirst,
                            None,
                        )
                    } else {
                        let mask = vec![true; schema_dim];
                        install_committed_runtime_mask(state, &schema, &mask)?;
                        (
                            mask,
                            credits.clone(),
                            equal_simplex(schema_dim),
                            TpeInitSource::EqualSimplexFallback,
                            Some("no_positive_explore_credits".to_string()),
                        )
                    };

                runtime.mask_committed = true;
                runtime.tpe_init_committed = true;
                runtime.effective_mask = effective_mask;
                runtime.selected_feature_names =
                    Self::selected_names(&schema, &runtime.effective_mask);
                runtime.selected_schema_indices = Self::selected_indices(&runtime.effective_mask);
                runtime.candidate_file_loaded = false;
                runtime.tpe_init_source = Some(source.clone());
                runtime.explore_credits_full = credits.clone();
                runtime.explore_credits_active = active_credits.clone();
                runtime.normalized_credit_init_v = normalized.clone();
                runtime.positive_credit_count = positive_count;
                runtime.positive_credit_sum = positive_sum;
                runtime.fallback_reason = fallback_reason.clone();
                Self::set_runtime_meta(state, runtime.clone());

                self.opt.enqueue_exact_then_neighbor_candidates(
                    state,
                    &normalized,
                    &mut self.rng,
                )?;

                if fallback_reason.is_some() {
                    eprintln!(
                        "[BOFuzz mask] mode=auto-credit status=fallback source=equal-simplex reason=no_positive_explore_credits active_dim={} mask={} normalized_init_v={:?}",
                        get_active_dim(state),
                        mask_to_bitstring(&runtime.effective_mask),
                        normalized
                    );
                } else {
                    eprintln!(
                        "[BOFuzz mask] mode=auto-credit status=selected source=explore-credits-exact-first top_k={} positive_count={} active_dim={} mask={} credits_full={:?} credits_active={:?} normalized_init_v={:?}",
                        runtime.credit_top_k,
                        positive_count,
                        get_active_dim(state),
                        mask_to_bitstring(&runtime.effective_mask),
                        credits,
                        active_credits,
                        normalized
                    );
                }
            }
        }

        validate_committed_vector_dimensions(state)?;
        Ok(())
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
                    maybe_export_runtime_data(state, false)?;
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

                self.commit_mask_and_tpe_initialization_before_first_tpe(state, mgr)?;

                if get_v_candidates(state).is_empty() {
                    return Err(Error::illegal_state(
                        "TPE initialization committed without available initial candidate"
                            .to_string(),
                    ));
                }

                let candidate = self.opt.next_untried_from_pool(state).ok_or_else(|| {
                    Error::illegal_state(
                        "BOFuzz failed to retrieve committed initial TPE candidate".to_string(),
                    )
                })?;
                self.start_pending_recompute(state, candidate)?;
                maybe_export_runtime_data(state, true)?;
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
                maybe_export_runtime_data(state, true)?;
                self.report_trials(state, mgr)?;

                let trials_len = self.opt.state.read().unwrap().trials.len();
                let simplex_sum = last_vec.iter().copied().sum::<f64>();
                let credits_sum = state
                    .metadata_map()
                    .get::<RuntimeCreditMeta>()
                    .map(|m| m.credits.iter().copied().sum::<f64>())
                    .or_else(|| {
                        state
                            .metadata_map()
                            .get::<ExploreCreditMeta>()
                            .map(|m| m.credits.iter().copied().sum::<f64>())
                    })
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
                    maybe_export_runtime_data(state, true)?;
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
