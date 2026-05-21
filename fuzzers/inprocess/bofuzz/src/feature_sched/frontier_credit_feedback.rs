use std::borrow::Cow;

use libafl::{
    common::HasMetadata,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    inputs::Input,
    Error,
};
use libafl_bolts::Named;

use super::features_map::EPS;
use super::frontier::{local_frontier_nodes, update_frontier_meta};
use super::metadata::{
    CoverageDeltaMeta, ExploreCreditEntry, ExploreCreditHistoryMeta, ExploreCreditMeta,
    FeaturesMatrixMeta, SancovAcfgMeta, SancovIndexesMetadata, TpeIterationMeta,
};
use crate::feature_sched::get_active_feature_names;

#[derive(Clone, Debug)]
pub struct FrontierCreditFeedback {
    name: Cow<'static, str>,
}

impl FrontierCreditFeedback {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("frontier_credit"),
        }
    }
}

impl Named for FrontierCreditFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for FrontierCreditFeedback
where
    S: HasMetadata,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for FrontierCreditFeedback
where
    I: Input,
    EM: EventFirer<I, S>,
    S: HasMetadata,
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
        _mgr: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        let Some(acfg) = state.metadata_map().get::<SancovAcfgMeta>().cloned() else {
            return Ok(());
        };
        if state.metadata_map().get::<FeaturesMatrixMeta>().is_none() {
            return Ok(());
        }

        let delta = state
            .metadata_map()
            .get::<CoverageDeltaMeta>()
            .cloned()
            .unwrap_or_default();
        if delta.newly_covered_sancov.is_empty() {
            return Ok(());
        }

        let testcase_covered = testcase
            .metadata_map()
            .get::<SancovIndexesMetadata>()
            .map(|m| m.list.clone())
            .unwrap_or_default();

        let changed = update_frontier_meta(state, &delta.newly_covered_sancov)?;
        if !changed {
            return Ok(());
        }

        let local_nodes =
            local_frontier_nodes(&delta.newly_covered_sancov, &testcase_covered, &acfg);
        let active_names = get_active_feature_names(state);
        if active_names.is_empty() {
            return Ok(());
        }

        let matrix = state
            .metadata_map()
            .get::<FeaturesMatrixMeta>()
            .ok_or_else(|| Error::illegal_state("FeaturesMatrixMeta missing".to_string()))?;

        let mut local_mass = vec![0.0; active_names.len()];
        for (i, name) in active_names.iter().enumerate() {
            let Some(arr) = matrix.matrix.get(name) else {
                continue;
            };
            for &node in &local_nodes {
                let value = arr.get(node).copied().unwrap_or(0.0);
                if value < 0.0 {
                    return Err(Error::illegal_state(
                        "negative feature value forbidden under simplex mode".to_string(),
                    ));
                }
                if value.is_finite() {
                    local_mass[i] += value;
                }
            }
        }

        let denom = local_mass.iter().copied().sum::<f64>();
        let mut credit_delta = vec![0.0; active_names.len()];
        if denom > EPS && delta.delta_edges > 0 {
            for (i, mass) in local_mass.iter().copied().enumerate() {
                let v = (delta.delta_edges as f64) * mass / denom;
                credit_delta[i] = v.max(0.0);
            }
        }

        let iteration = state
            .metadata_map()
            .get::<TpeIterationMeta>()
            .map(|m| m.current_iteration)
            .unwrap_or(delta.iteration);

        let cumulative = {
            let meta = state
                .metadata_map_mut()
                .get_or_insert_with::<ExploreCreditMeta>(Default::default);
            if meta.credits.len() != active_names.len() {
                meta.credits.resize(active_names.len(), 0.0);
            }
            meta.iteration = iteration;
            meta.total_delta_edges = meta.total_delta_edges.saturating_add(delta.delta_edges);
            for (c, d) in meta.credits.iter_mut().zip(credit_delta.iter()) {
                *c = (*c + *d).max(0.0);
            }
            meta.credits.clone()
        };

        let entry = ExploreCreditEntry {
            iteration,
            corpus_id: None,
            delta_edges: delta.delta_edges,
            frontier_nodes: local_nodes,
            credit_delta,
            cumulative_credits: cumulative,
        };
        state
            .metadata_map_mut()
            .get_or_insert_with::<ExploreCreditHistoryMeta>(Default::default)
            .entries
            .push(entry);

        Ok(())
    }
}
