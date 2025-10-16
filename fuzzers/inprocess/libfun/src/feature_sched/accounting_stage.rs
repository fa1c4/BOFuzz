/*
feature_sched/accounting_stage.rs: calculate the features factor and set to metadata
*/
use std::time::{Instant, Duration};
use std::sync::atomic::Ordering;
use std::path::Path;
use std::fs::OpenOptions;
use std::io::Write;
use libafl::{
    stages::Stage, executors::Executor, events::EventFirer,
    observers::{ObserversTuple, MapObserver},
    executors::HasObservers,
    common::HasMetadata,
    state::HasCorpus,
    inputs::BytesInput,
    corpus::Corpus,
    Error,
};
use libafl_bolts::{tuples::{Handle, MatchNameRef}, AsIter};
use super::metadata::{PathWeightMeta, GlobalStatsMeta, FeaturesMapMeta};
use super::stats::WeightStats;
use crate::feature_sched::{FEATURES_ACTIVE, FUZZ_START, features_enabled, 
                            set_features_enabled, set_factor_params, SancovIndexesMetadata};

use libafl::schedulers::testcase_score::ExternalPerfMultMeta;
use super::factor::compute_factor;
use crate::feature_sched::get_factor_params;

pub struct FeaturesAccountingStage<C> {
    // pub map_name: &'static str,
    pub handle: Handle<C>,
    pub _p: core::marker::PhantomData<C>,
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
        if !features_enabled() {
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

        // // 1) read hit indices from SancovIndexesMetadata
        // let indices: Vec<usize> = {
        //     let entry = state.corpus().get(cid)?.borrow();
        //     match entry.metadata_map().get::<SancovIndexesMetadata>() {
        //         Some(meta) => meta.list.clone(), // field, not method, in your libafl
        //         None => return Ok(()), // nothing tracked yet
        //     }
        // };

        // // 2) features map
        // let feats = state
        //     .metadata_map()
        //     .get::<FeaturesMapMeta>()
        //     .expect("FeaturesMapMeta not in State")
        //     .feats
        //     .as_slice();

        // // 3) accumulate path weight
        // let mut w = 0.0;
        // for &i in &indices {
        //     if i < feats.len() { w += feats[i]; }
        // }

        // 1-3) borrow and accumulate
        let w = {
            let entry = state.corpus().get(cid)?.borrow();
            let meta = match entry.metadata_map().get::<SancovIndexesMetadata>() {
                Some(m) => m,
                None => return Ok(()),
            };
            let feats = state.metadata_map().get::<FeaturesMapMeta>()
                .expect("FeaturesMapMeta not in State").feats.as_slice();
        
            meta.list.iter().fold(0.0, |acc, &i| acc + feats.get(i).copied().unwrap_or(0.0))
        };

        // 4) write PathWeightMeta back to current testcase
        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(PathWeightMeta { w });
        }

        // 5) calculate feat_factor
        let feat_factor = {
            let params = get_factor_params();
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

        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> { 
        let start_time = unsafe { FUZZ_START.unwrap_or_else(Instant::now) }; // Use FUZZ_START or set current time if not initialized
        let elapsed = start_time.elapsed();

        // hours delay before enabling features (modify the duration as needed)
        let cold_start_duration = Duration::from_secs(12 * 60 * 60);

        // If elapsed time is greater than or equal to the cold start duration, enable the feature
        if !FEATURES_ACTIVE.load(Ordering::Relaxed) && elapsed >= cold_start_duration {
            // Log and enable the feature
            FEATURES_ACTIVE.store(true, Ordering::Relaxed);
            let mut params = get_factor_params();
            params.alpha = 1.0;
            set_factor_params(params);
            set_features_enabled(true);

            return Ok(true); // Return true to trigger `perform`
        }

        Ok(false) // Return false if the cold start time has not yet elapsed
    }
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> { Ok(()) }
}
