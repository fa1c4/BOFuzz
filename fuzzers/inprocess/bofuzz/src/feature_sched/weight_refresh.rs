use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;

use libafl::common::HasMetadata;
use libafl::corpus::{Corpus, CorpusId};
use libafl::schedulers::testcase_score::ExternalPerfMultMeta;
use libafl::state::HasCorpus;
use libafl::Error;

use super::factor::compute_factor;
use super::metadata::{
    FrontierMeta, GlobalStatsMeta, PathWeightMeta, SancovAcfgMeta, SancovIndexesMetadata,
    TestcaseFeatureWeightMeta, WeightComputeMode,
};
use super::stats::WeightStats;
use crate::feature_sched::get_factor_params;

#[derive(Clone, Debug)]
pub struct FrontierSnapshot {
    pub f_prev: Vec<bool>,
    pub f_next: Vec<bool>,
    pub successors: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
pub struct TestcaseSnapshot {
    pub corpus_id: CorpusId,
    pub covered_sancov: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct CorpusWeightSnapshot {
    pub iteration: u64,
    pub mode: WeightComputeMode,
    pub feature_weights_by_sancov: Vec<f64>,
    pub frontier: Option<FrontierSnapshot>,
    pub testcases: Vec<TestcaseSnapshot>,
}

#[derive(Clone, Debug)]
pub struct WeightRecomputeResult {
    pub iteration: u64,
    pub mode: WeightComputeMode,
    pub per_testcase: Vec<TestcaseWeightResult>,
}

#[derive(Clone, Debug)]
pub struct TestcaseWeightResult {
    pub corpus_id: CorpusId,
    pub weight: f64,
}

pub fn build_corpus_weight_snapshot<I, S>(
    state: &S,
    iteration: u64,
    mode: WeightComputeMode,
    feature_weights_by_sancov: Vec<f64>,
) -> Result<CorpusWeightSnapshot, Error>
where
    S: HasCorpus<I> + HasMetadata,
{
    let frontier = if mode == WeightComputeMode::Frontier {
        let fm = state.metadata_map().get::<FrontierMeta>().cloned();
        let acfg = state.metadata_map().get::<SancovAcfgMeta>().cloned();
        match (fm, acfg) {
            (Some(fm), Some(acfg)) => Some(FrontierSnapshot {
                f_prev: fm.f_prev,
                f_next: fm.f_next,
                successors: acfg.successors,
            }),
            _ => None,
        }
    } else {
        None
    };

    let mut testcases = Vec::with_capacity(state.corpus().count());
    for corpus_id in state.corpus().ids() {
        let covered_sancov = state
            .corpus()
            .get(corpus_id)?
            .borrow()
            .metadata_map()
            .get::<SancovIndexesMetadata>()
            .map(|m| m.list.clone())
            .unwrap_or_default();
        testcases.push(TestcaseSnapshot {
            corpus_id,
            covered_sancov,
        });
    }

    Ok(CorpusWeightSnapshot {
        iteration,
        mode,
        feature_weights_by_sancov,
        frontier,
        testcases,
    })
}

fn path_weight(feature_weights: &[f64], covered: &[usize]) -> f64 {
    covered
        .iter()
        .map(|&i| feature_weights.get(i).copied().unwrap_or(0.0))
        .filter(|w| w.is_finite() && *w > 0.0)
        .sum()
}

fn frontier_weight(feature_weights: &[f64], frontier: &FrontierSnapshot, covered: &[usize]) -> f64 {
    let mut total = 0.0;
    let mut next_seen = HashSet::new();

    for &node in covered {
        if frontier.f_prev.get(node).copied().unwrap_or(false) {
            total += feature_weights.get(node).copied().unwrap_or(0.0).max(0.0);
        }
        if let Some(succs) = frontier.successors.get(node) {
            for &succ in succs {
                if frontier.f_next.get(succ).copied().unwrap_or(false) {
                    next_seen.insert(succ);
                }
            }
        }
    }

    for node in next_seen {
        total += feature_weights.get(node).copied().unwrap_or(0.0).max(0.0);
    }

    if total.is_finite() {
        total
    } else {
        0.0
    }
}

pub fn compute_weights(snapshot: CorpusWeightSnapshot) -> WeightRecomputeResult {
    let mut per_testcase = Vec::with_capacity(snapshot.testcases.len());
    for tc in snapshot.testcases {
        let weight = match snapshot.mode {
            WeightComputeMode::Path => {
                path_weight(&snapshot.feature_weights_by_sancov, &tc.covered_sancov)
            }
            WeightComputeMode::Frontier => snapshot
                .frontier
                .as_ref()
                .map(|f| {
                    frontier_weight(&snapshot.feature_weights_by_sancov, f, &tc.covered_sancov)
                })
                .unwrap_or(0.0),
        };
        per_testcase.push(TestcaseWeightResult {
            corpus_id: tc.corpus_id,
            weight,
        });
    }
    WeightRecomputeResult {
        iteration: snapshot.iteration,
        mode: snapshot.mode,
        per_testcase,
    }
}

pub fn spawn_weight_recompute_worker(
    snapshot: CorpusWeightSnapshot,
) -> (
    thread::JoinHandle<()>,
    mpsc::Receiver<WeightRecomputeResult>,
) {
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = compute_weights(snapshot);
        let _ = tx.send(result);
    });
    (handle, rx)
}

pub fn publish_weight_recompute_result<I, S>(
    state: &mut S,
    result: WeightRecomputeResult,
) -> Result<(), Error>
where
    S: HasCorpus<I> + HasMetadata,
{
    let mut stats = WeightStats::default();
    for item in &result.per_testcase {
        stats.update(item.weight);
        let mut entry = state.corpus().get(item.corpus_id)?.borrow_mut();
        match result.mode {
            WeightComputeMode::Frontier => {
                entry.add_metadata(TestcaseFeatureWeightMeta {
                    iteration: result.iteration,
                    weight: item.weight,
                    mode: result.mode,
                });
            }
            WeightComputeMode::Path => {
                entry.add_metadata(PathWeightMeta { w: item.weight });
            }
        }
    }
    state.add_metadata(GlobalStatsMeta { stats });

    let params = get_factor_params(state);
    for item in &result.per_testcase {
        let factor = {
            let entry = state.corpus().get(item.corpus_id)?.borrow();
            compute_factor(&params, state, &*entry)
        };
        let mut entry = state.corpus().get(item.corpus_id)?.borrow_mut();
        entry.add_metadata(ExternalPerfMultMeta(factor));
    }

    Ok(())
}
