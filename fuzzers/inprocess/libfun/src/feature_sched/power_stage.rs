use core::marker::PhantomData;

use libafl::{
    corpus::Corpus,             // current(), get()
    Error,
    executors::{Executor, HasObservers},
    events::EventFirer,
    inputs::Input,
    observers::ObserversTuple,
    schedulers::testcase_score::{CorpusPowerTestcaseScore, TestcaseScore},
    stages::Stage,
    state::HasCorpus,
    common::HasMetadata,
};

use crate::feature_sched::{compute_factor, features_enabled, get_factor_params};

// use features_map to change FAST perf_score Stage of Power:
// - first calculate base perf_score (original CorpusPowerTestcaseScore::compute)
// - then multiply features factor
// - convert energy to times of calling StdMutationalStage
pub struct FeatureAwarePowerStage<T, I> {
    inner: T,
    energy_divisor: f64,
    _phantom: PhantomData<I>,
}

impl<T, I> FeatureAwarePowerStage<T, I> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            energy_divisor: 100.0, // aligns with AFL-style scaling
            _phantom: PhantomData,
        }
    }

    #[allow(dead_code)]
    pub fn with_divisor(inner: T, energy_divisor: f64) -> Self {
        Self {
            inner,
            energy_divisor,
            _phantom: PhantomData,
        }
    }
}

impl<E, EM, I, S, Z, T> Stage<E, EM, S, Z> for FeatureAwarePowerStage<T, I>
where
    I: Input,
    S: HasCorpus<I> + HasMetadata,
    E: Executor<EM, I, S, Z> + HasObservers,
    EM: EventFirer<I, S>,
    E::Observers: ObserversTuple<I, S>,
    T: Stage<E, EM, S, Z>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        mgr: &mut EM,
    ) -> Result<(), Error> {
        // get current corpus entry
        let sref: &S = &*state;
        let cid = sref
        .corpus()
        .current()
        .ok_or_else(|| Error::unknown("No current corpus id".to_string()))?;
    
        let mut entry = sref.corpus().get(cid)?.borrow_mut();

        // 1) get the perf_score of FAST
        let mut perf = CorpusPowerTestcaseScore::compute(sref, &mut *entry)?;

        // 2) multiply features factor if enable
        if features_enabled() {
            let params = get_factor_params();
            let factor = compute_factor(params, sref, &*entry);
            perf *= factor;
        }
        drop(entry);

        // 3) perf_score -> iter times
        // aligns with AFL: 100 is 1 time
        let iters: usize = ((perf / self.energy_divisor).max(1.0)) as usize;

        for _ in 0..iters {
            self.inner.perform(fuzzer, executor, state, mgr)?;
        }
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> { Ok(false) }
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> { Ok(()) }
}
