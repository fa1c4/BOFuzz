use libafl::{
    common::HasMetadata,
    corpus::Corpus,
    events::{Event, EventFirer},
    executors::{Executor, HasObservers},
    inputs::BytesInput,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::{MapObserver, ObserversTuple},
    schedulers::testcase_score::ExternalPerfMultMeta,
    stages::Stage,
    state::HasCorpus,
    Error,
};
use libafl_bolts::{
    tuples::{Handle, MatchNameRef},
    AsIter,
};

use super::factor::compute_factor;
use super::metadata::{
    PathWeightMeta, TestcaseFeatureWeightMeta, WeightComputeMode, WeightComputeModeMeta,
};
use crate::feature_sched::SancovIndexesMetadata;
use crate::feature_sched::{
    get_active_dim, get_current_weight_vec, get_factor_params, get_feat0, get_feat_exists,
    get_feat_mode, get_features_active, get_features_enabled, get_v_candidates, set_feat0,
};

pub struct FeaturesAccountingStage<C> {
    pub handle: Handle<C>,
    pub _p: core::marker::PhantomData<C>,
}

impl<C> FeaturesAccountingStage<C> {
    pub fn new(handle: Handle<C>) -> Self {
        Self {
            handle,
            _p: core::marker::PhantomData,
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
        mgr: &mut EM,
    ) -> Result<(), Error> {
        let Some(cid_ref) = state.corpus().current() else {
            return Ok(());
        };
        let cid = *cid_ref;

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

        if !get_features_enabled(state) {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            let _ = entry.remove_metadata::<ExternalPerfMultMeta>();
            return Ok(());
        }

        let feat0 = state
            .metadata_map()
            .get::<super::metadata::FeaturesMapMeta>()
            .and_then(|m| m.feats.first().copied())
            .unwrap_or(0.0);
        set_feat0(state, feat0);

        let params = get_factor_params(state);
        let factor = {
            let entry = state.corpus().get(cid)?.borrow();
            compute_factor(&params, state, &*entry)
        };
        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(ExternalPerfMultMeta(factor));
        }

        let mode = state
            .metadata_map()
            .get::<WeightComputeModeMeta>()
            .map(|m| m.mode)
            .unwrap_or_default();
        let weight = {
            let entry = state.corpus().get(cid)?.borrow();
            match mode {
                WeightComputeMode::Frontier => entry
                    .metadata_map()
                    .get::<TestcaseFeatureWeightMeta>()
                    .map(|m| m.weight)
                    .unwrap_or(0.0),
                WeightComputeMode::Path => entry
                    .metadata_map()
                    .get::<PathWeightMeta>()
                    .map(|m| m.w)
                    .unwrap_or(0.0),
            }
        };

        let active_dim = get_active_dim(state);
        let params = get_factor_params(state);
        let v_now = get_current_weight_vec(state);
        let cand_cnt = get_v_candidates(state).len();
        let v_str = fmt_vec_short(&v_now, active_dim);
        let simplex_sum = v_now.iter().copied().sum::<f64>();

        let summary = format!(
            "enabled={}, active={}, feat_mode={}, feat_exists={}, mode={:?}, alpha={:.2}, beta={:.2}, gmin={:.2}, gmax={:.2}, use_tanh={}, active_dim={}, v_candidates_len={}, current_v={}, simplex_sum={:.6}, feat0={:.3}, weight={:.3}, factor={:.3}",
            get_features_enabled(state),
            get_features_active(state),
            get_feat_mode(state),
            get_feat_exists(state),
            mode,
            params.alpha,
            params.beta,
            params.gmin,
            params.gmax,
            params.use_tanh,
            active_dim,
            cand_cnt,
            v_str,
            simplex_sum,
            get_feat0(state),
            weight,
            factor,
        );

        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: "features-info".into(),
                value: UserStats::new(UserStatsValue::String(summary.into()), AggregatorOps::None),
                phantom: core::marker::PhantomData,
            },
        )?;

        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(false)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
