use libafl::{
    stages::Stage, executors::Executor, events::EventFirer,
    observers::ObserversTuple,
    Error,
    feedbacks::MapIndexesMetadata,
};
use libafl::executors::HasObservers;
use libafl::common::HasMetadata;
use libafl::state::HasCorpus;
use libafl::inputs::BytesInput;
use libafl::corpus::Corpus; // current(), get(), get_mut()     
use libafl_bolts::tuples::MatchName;       
use super::metadata::{PathWeightMeta, GlobalStatsMeta, FeaturesMapMeta};
use super::stats::WeightStats;
use crate::feature_sched::features_enabled;

pub struct FeaturesAccountingStage {
    pub map_name: &'static str, // like "sancov"
}

impl Default for FeaturesAccountingStage {
    fn default() -> Self { Self { map_name: "sancov" } }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for FeaturesAccountingStage
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers,
    EM: EventFirer<BytesInput, S>,
    S: HasMetadata + HasCorpus<BytesInput>,
    E::Observers: ObserversTuple<BytesInput, S>,
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
            return Ok(());
        }

        let Some(cid_ref) = state.corpus().current() else { return Ok(()); };
        let cid = *cid_ref;

        // 1) read hit indices from MapIndexesMetadata
        let indices: Vec<usize> = {
            let entry = state.corpus().get(cid)?.borrow();
            match entry.metadata_map().get::<MapIndexesMetadata>() {
                Some(meta) => meta.list.clone(), // field, not method, in your libafl
                None => return Ok(()), // nothing tracked yet
            }
        };

        // 2) features map
        let feats = state
            .metadata_map()
            .get::<FeaturesMapMeta>()
            .expect("FeaturesMapMeta not in State")
            .feats
            .as_slice();

        // 3) accumulate path weight
        let mut w = 0.0;
        for &i in &indices {
            if i < feats.len() { w += feats[i]; }
        }

        // 4) write PathWeightMeta back to current testcase
        {
            let mut entry = state.corpus().get(cid)?.borrow_mut();
            entry.add_metadata(PathWeightMeta { w });
        }

        // 5) update global stats
        if !state.has_metadata::<GlobalStatsMeta>() {
            state.add_metadata(GlobalStatsMeta { stats: WeightStats::default() });
        }
        let meta = state.metadata_map_mut().get_mut::<GlobalStatsMeta>().unwrap();
        meta.stats.update(w);

        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> { Ok(false) }
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> { Ok(()) }
}
