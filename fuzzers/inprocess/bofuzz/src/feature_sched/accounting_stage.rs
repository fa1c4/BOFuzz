use super::metadata::{FeaturesMapMeta, GlobalStatsMeta, PathWeightMeta, TpeHistoryMeta};
use super::stats::WeightStats;
use libafl::{
    common::HasMetadata,
    corpus::Corpus,
    events::{Event, EventFirer},
    executors::Executor,
    executors::HasObservers,
    inputs::BytesInput,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::{MapObserver, ObserversTuple},
    stages::Stage,
    state::HasCorpus,
    Error,
};
use libafl_bolts::{
    current_time,
    tuples::{Handle, MatchNameRef},
    AsIter,
};
use std::time::Duration;

use super::factor::compute_factor;
use crate::feature_sched::get_feat_mode;
use libafl::schedulers::testcase_score::ExternalPerfMultMeta;

use crate::feature_sched::SancovIndexesMetadata;
use crate::feature_sched::{
    get_active_dim, get_active_feature_names, get_alpha_init, get_current_weight_vec,
    get_explore_time, get_factor_params, get_feat0, get_feat_exists, get_features_active,
    get_features_enabled, get_fuzz_start, get_v_candidates, set_factor_params, set_feat0,
    set_features_active,
};

pub struct FeaturesAccountingStage<C> {
    pub handle: Handle<C>,
    pub _p: core::marker::PhantomData<C>,
    last_emit_tpe_ts: u64,
    last_emit_trials_len: usize,
}

impl<C> FeaturesAccountingStage<C> {
    pub fn new(handle: Handle<C>) -> Self {
        Self {
            handle,
            _p: core::marker::PhantomData,
            last_emit_tpe_ts: 0,
            last_emit_trials_len: 0,
        }
    }
}

fn fmt_vec_short(v: &[f64], maxn: usize) -> String {
    let take = v.len().min(maxn);
    let mut s = v[..take]
        .iter()
        .map(|x| format!("{:.3}", x))
        .collect::<Vec<_>>()
        .join(",");
    if v.len() > take {
        s.push_str(",...");
    }
    format!("[{}](len={})", s, v.len())
}

impl<E, EM, S, Z, C> Stage<E, EM, S, Z> for FeaturesAccountingStage<C>
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers,
    EM: EventFirer<BytesInput, S>,
    S: HasMetadata + HasCorpus<BytesInput>,
    E::Observers: ObserversTuple<BytesInput, S> + MatchNameRef,
    C: MapObserver<Entry = u8> + for<'it> AsIter<'it, Item = u8>,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        _mgr: &mut EM,
    ) -> Result<(), Error> {
        if !get_features_enabled(state) {
            if let Some(cid_ref) = state.corpus().current() {
                let cid = *cid_ref;
                let mut entry = state.corpus().get(cid)?.borrow_mut();
                let _ = entry.remove_metadata::<ExternalPerfMultMeta>();
            }
            return Ok(());
        }

        let Some(cid_ref) = state.corpus().current() else {
            return Ok(());
        };
        let cid = *cid_ref;

        {
            let need_fill = {
                let entry = state.corpus().get(cid)?.borrow();
                entry
                    .metadata_map()
                    .get::<SancovIndexesMetadata>()
                    .is_none()
            };
            if need_fill {
                let obs_ref = executor.observers();
                let sancov: &C = obs_ref
                    .get(&self.handle)
                    .ok_or_else(|| Error::unknown("sancov observer not found".to_string()))?;

                let init = sancov.initial();
                let mut idx = Vec::new();
                for (i, v) in sancov.as_iter().enumerate() {
                    if *v != init {
                        idx.push(i);
                    }
                }
                if !idx.is_empty() {
                    let mut entry = state.corpus().get(cid)?.borrow_mut();
                    entry.add_metadata(SancovIndexesMetadata::new(idx));
                }
            }
        }

        let indices: Vec<usize> = {
            let entry = state.corpus().get(cid)?.borrow();
            let meta = match entry.metadata_map().get::<SancovIndexesMetadata>() {
                Some(m) => m,
                None => return Ok(()),
            };
            meta.list.clone()
        };
        let (feat0, w) = {
            let feats_ref = state
                .metadata_map()
                .get::<FeaturesMapMeta>()
                .expect("FeaturesMapMeta not in State");
            let feats = feats_ref.feats.as_slice();

            let feat0 = *feats.get(0).unwrap_or(&0.0);

            let w = indices
                .iter()
                .fold(0.0, |acc, &i| acc + feats.get(i).copied().unwrap_or(0.0));

            (feat0, w)
        };
        set_feat0(state, feat0);

        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(PathWeightMeta { w });
        }

        let feat_factor = {
            let params = get_factor_params(state);
            let entry_borrow = state.corpus().get(cid)?.borrow();
            compute_factor(&params, state, &*entry_borrow)
        };
        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(ExternalPerfMultMeta(feat_factor));
        }

        if !state.has_metadata::<GlobalStatsMeta>() {
            state.add_metadata(GlobalStatsMeta {
                stats: WeightStats::default(),
            });
        }
        let meta = state
            .metadata_map_mut()
            .get_mut::<GlobalStatsMeta>()
            .unwrap();
        meta.stats.update(w);

        let (tpe_ts, tpe_trials_len) =
            if let Some(tm) = state.metadata_map().get::<TpeHistoryMeta>() {
                (tm.last_check_ms.unwrap_or(0), tm.trials.len())
            } else {
                (0, 0)
            };
        let should_fire =
            tpe_ts > self.last_emit_tpe_ts || tpe_trials_len > self.last_emit_trials_len;

        if should_fire {
            self.last_emit_tpe_ts = tpe_ts;
            self.last_emit_trials_len = tpe_trials_len;

            let enabled = get_features_enabled(state);
            let active = get_features_active(state);
            let feat_exists = get_feat_exists(state);
            let feat_mode = get_feat_mode(state);
            let active_dim = get_active_dim(state);

            let params = get_factor_params(state);
            let v_now = get_current_weight_vec(state);
            let cand_cnt = get_v_candidates(state).len();
            let v_str = fmt_vec_short(&v_now, 1 + active_dim);

            let summary = format!(
                "enabled={}, active={}, feat_mode={}, feat_exists={}, \
                alpha={:.2}, beta={:.2}, gmin={:.2}, gmax={:.2}, use_tanh={}, \
                active_dim={}, v_candidates_len={}, current_v={}, feat0={:.3}, path_w={:.3}, factor={:.3}",
                enabled, active, feat_mode, feat_exists,
                params.alpha, params.beta, params.gmin, params.gmax, params.use_tanh,
                active_dim, cand_cnt, v_str, get_feat0(state), w, feat_factor
            );

            _mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: "features-info".into(),
                    value: UserStats::new(
                        UserStatsValue::String(summary.into()),
                        AggregatorOps::None,
                    ),
                    phantom: core::marker::PhantomData,
                },
            )?;
        }

        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        if get_feat_mode(_state) == 0 {
            return Ok(false);
        }
        if !get_feat_exists(_state) {
            return Ok(false);
        }

        if get_features_active(_state) {
            return Ok(true);
        }

        let now_ms = current_time().as_millis() as u64;
        let start_ms = get_fuzz_start(_state);
        let elapsed = Duration::from_millis(now_ms.saturating_sub(start_ms));

        let explore_duration = Duration::from_secs(get_explore_time(_state));

        if !get_features_active(_state) && elapsed >= explore_duration {
            set_features_active(_state, true);
            let mut params = get_factor_params(_state);
            let alpha_init_val = get_alpha_init(_state);
            params.alpha = if alpha_init_val.is_nan() {
                1.0
            } else {
                alpha_init_val
            };
            set_factor_params(_state, params);

            return Ok(true);
        }

        Ok(false)
    }
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
