/*
feature_sched/accounting_stage.rs: calculate the features factor and set to metadata
*/
use std::time::Duration;
use libafl::{
    stages::Stage, executors::Executor, events::{EventFirer, Event},
    observers::{ObserversTuple, MapObserver},
    executors::HasObservers,
    common::HasMetadata,
    state::HasCorpus,
    inputs::BytesInput,
    corpus::Corpus,
    Error,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
};
use libafl_bolts::{tuples::{Handle, MatchNameRef}, AsIter, current_time};
use super::metadata::{PathWeightMeta, GlobalStatsMeta, FeaturesMapMeta};
use super::stats::WeightStats;

use libafl::schedulers::testcase_score::ExternalPerfMultMeta;
use crate::feature_sched::get_feat_mode;
use super::factor::compute_factor;

use crate::feature_sched::SancovIndexesMetadata;
use crate::feature_sched::{get_features_enabled, set_factor_params, get_v_candidates, get_factor_params, 
    get_feat_exists, set_feat0, get_feat0, get_alpha_init, get_explore_time, 
    get_features_active, set_features_active, get_fuzz_start, get_current_weight_vec};

pub struct FeaturesAccountingStage<C> {
    // pub map_name: &'static str,
    pub handle: Handle<C>,
    pub _p: core::marker::PhantomData<C>,
}

fn fmt_vec_short(v: &[f64], maxn: usize) -> String {
    let take = v.len().min(maxn);
    let mut s = v[..take].iter().enumerate()
        .map(|(_, x)| format!("{:.3}", x))
        .collect::<Vec<_>>()
        .join(",");
    if v.len() > take { s.push_str(",..."); }
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
        // disable features factor then return directly
        if !get_features_enabled(state) {
            if let Some(cid_ref) = state.corpus().current() {
                let cid = *cid_ref;
                let mut entry = state.corpus().get(cid)?.borrow_mut();
                let _ = entry.remove_metadata::<ExternalPerfMultMeta>();
            }
            return Ok(());
        }

        let Some(cid_ref) = state.corpus().current() else { return Ok(()); };
        let cid = *cid_ref;

        // 0) corpus entry sancov indices lazy fill | maybe overhead
        {
            let need_fill = {
                let entry = state.corpus().get(cid)?.borrow();
                entry.metadata_map().get::<SancovIndexesMetadata>().is_none()
            };
            if need_fill {
                let obs_ref = executor.observers();
                let sancov: &C = obs_ref
                    .get(&self.handle)
                    .ok_or_else(|| Error::unknown("sancov observer not found".to_string()))?;
    
                let init = sancov.initial();
                let mut idx = Vec::new();
                for (i, v) in sancov.as_iter().enumerate() {
                    if *v != init { idx.push(i); }
                }
                if !idx.is_empty() {
                    let mut entry = state.corpus().get(cid)?.borrow_mut();
                    entry.add_metadata(SancovIndexesMetadata::new(idx));
                }
            }
        }

        // 1-3) borrow and accumulate
        // let w = {
        //     let entry = state.corpus().get(cid)?.borrow();
        //     let meta = match entry.metadata_map().get::<SancovIndexesMetadata>() {
        //         Some(m) => m,
        //         None => return Ok(()),
        //     };
        //     let feats = state.metadata_map().get::<FeaturesMapMeta>()
        //         .expect("FeaturesMapMeta not in State").feats.as_slice();

        //     set_feat0(state, *feats.get(0).unwrap_or(&0.0));
        
        //     meta.list.iter().fold(0.0, |acc, &i| acc + feats.get(i).copied().unwrap_or(0.0))
        // };
        // 1) read indices
        let indices: Vec<usize> = {
            let entry = state.corpus().get(cid)?.borrow();
            let meta = match entry.metadata_map().get::<SancovIndexesMetadata>() {
                Some(m) => m,
                None => return Ok(()),
            };
            meta.list.clone()
        };
        // 2-3) read features & accumulate path weight
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

        // 4) write PathWeightMeta back to current testcase
        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(PathWeightMeta { w });
        }

        // 5) calculate feat_factor
        let feat_factor = {
            let params = get_factor_params(state);
            let entry_borrow = state.corpus().get(cid)?.borrow();
            compute_factor(&params, state, &*entry_borrow)
        };
        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(ExternalPerfMultMeta(feat_factor));
        }

        // 6) update global stats
        if !state.has_metadata::<GlobalStatsMeta>() {
            state.add_metadata(GlobalStatsMeta { stats: WeightStats::default() });
        }
        let meta = state.metadata_map_mut().get_mut::<GlobalStatsMeta>().unwrap();
        meta.stats.update(w);

        // message monitor callback
        {
            let enabled = get_features_enabled(state);
            let active  = get_features_active(state);
            let feat_exists = get_feat_exists(state);
            let feat_mode = get_feat_mode(state);

            let params = get_factor_params(state);
            let v_now = get_current_weight_vec(state);
            let cand_cnt = get_v_candidates(state).len();
            let v_str = fmt_vec_short(&v_now, 8);

            let summary = format!(
                "enabled={}, active={}, feat_mode={}, feat_exists={}, \
                alpha={:.2}, beta={:.2}, gmin={:.2}, gmax={:.2}, use_tanh={}, \
                v_candidates_len={}, current_v={}, feat0={:.3}, path_w={:.3}, factor={:.3}",
                enabled, active, feat_mode, feat_exists,
                params.alpha, params.beta, params.gmin, params.gmax, params.use_tanh,
                cand_cnt, v_str, get_feat0(state), w, feat_factor
            );

            _mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: "features-info".into(),
                    value: UserStats::new(UserStatsValue::String(summary.into()), AggregatorOps::None),
                    phantom: core::marker::PhantomData,
                },
            )?;
        }

        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> { 
        // cold fuzzing forever when feat_mode==0 
        if get_feat_mode(_state) == 0 {
            return Ok(false);
        }
        // if no features_map then cold fuzzing forever
        if !get_feat_exists(_state) {
            return Ok(false);
        }

        let now_ms = current_time().as_millis() as u64;
        let start_ms = get_fuzz_start(_state);
        let elapsed = Duration::from_millis(now_ms.saturating_sub(start_ms));

        // hours delay before enabling features (modify the duration as needed)
        // let explore_duration = Duration::from_secs(12 * 60 * 60);
        // let explore_duration = Duration::from_secs(30);
        let explore_duration = Duration::from_secs(get_explore_time(_state));

        // If elapsed time is greater than or equal to the cold start duration, enable the feature
        if !get_features_active(_state) && elapsed >= explore_duration {
            // Log and enable the feature
            set_features_active(_state, true);
            let mut params = get_factor_params(_state);
            let alpha_init_val = get_alpha_init(_state);
            params.alpha = if alpha_init_val.is_nan() { 1.0 } else { alpha_init_val };
            set_factor_params(_state, params);

            return Ok(true); // Return true to trigger `perform`
        }

        Ok(false) // Return false if the cold start time has not yet elapsed
    }
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> { Ok(()) }
}
