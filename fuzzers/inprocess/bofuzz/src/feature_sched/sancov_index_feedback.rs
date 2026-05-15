/*
features_sched/sancov_index_feedback.rs: update sancov indices
*/
use crate::feature_sched::SancovIndexesMetadata;
use libafl::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    inputs::Input,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::MapObserver,
    Error,
};
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    AsIter, Named,
};
use std::borrow::Cow;

#[derive(Clone, Debug)]
pub struct SancovIndexFeedback<C>
where
    C: MapObserver<Entry = u8> + Named,
{
    name: Cow<'static, str>,
    handle: Handle<C>,
    _p: core::marker::PhantomData<C>,
}

impl<C> SancovIndexFeedback<C>
where
    C: MapObserver<Entry = u8> + Named,
{
    pub fn new(map: &C) -> Self {
        Self {
            name: map.name().clone(),
            handle: map.handle(),
            _p: core::marker::PhantomData,
        }
    }
}

impl<C> Named for SancovIndexFeedback<C>
where
    C: MapObserver<Entry = u8> + Named,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S, C> StateInitializer<S> for SancovIndexFeedback<C>
where
    C: MapObserver<Entry = u8> + Named,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S, C> Feedback<EM, I, OT, S> for SancovIndexFeedback<C>
where
    I: Input,
    EM: EventFirer<I, S>,
    OT: MatchNameRef,
    S: HasNamedMetadata,
    C: MapObserver<Entry = u8> + Named + for<'it> AsIter<'it, Item = u8>,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        mgr: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        let map: &C = observers
            .get(&self.handle)
            .ok_or_else(|| Error::unknown("sancov observer not found".to_string()))?;

        let initial = map.initial();
        let mut idx = Vec::new();
        for (i, v) in map.as_iter().enumerate() {
            if *v != initial {
                idx.push(i);
            }
        }
        if !idx.is_empty() {
            testcase.add_metadata(SancovIndexesMetadata::new(idx));
        }

        // [option: report coverage info]
        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: self.name.clone(),
                value: UserStats::new(
                    UserStatsValue::Ratio(
                        testcase
                            .metadata_map()
                            .get::<SancovIndexesMetadata>()
                            .map(|m| m.list.len())
                            .unwrap_or(0) as u64,
                        map.len() as u64,
                    ),
                    AggregatorOps::Avg,
                ),
                phantom: core::marker::PhantomData,
            },
        )?;

        Ok(())
    }
}
