// feature_sched/tpe_stage.rs
use std::time::Instant;
use libafl::{
    stages::Stage, executors::Executor, events::EventFirer,
    inputs::BytesInput, executors::HasObservers, state::HasCorpus,
    observers::ObserversTuple, Error,
};
use libafl::common::HasMetadata;
use libafl::corpus::Corpus;
use libafl::events::Event;
use libafl::monitors::{AggregatorOps, UserStats, UserStatsValue};
use libafl::observers::MapObserver;
use libafl_bolts::tuples::Handle;
use libafl::observers::HitcountsMapObserver;
use libafl::observers::map::StdMapObserver;
use libafl_bolts::tuples::MatchNameRef;
use libafl_bolts::Named;
use libafl::HasNamedMetadata;
use libafl::feedbacks::MapFeedbackMetadata;

use super::tpe::{TpeOptimizer, TpeParams};
use super::{
    get_factor_params, set_factor_params,
    features_map::{apply_v_to_features},
};
use libafl_bolts::rands::StdRand;

use crate::feature_sched::{get_features_enabled, get_tpe_satisfied, get_v_candidates, get_current_weight_vec};

pub struct TpeStage {
    pub opt: TpeOptimizer,
    rng: StdRand,
    edges_name: String,
}

impl TpeStage {
    pub fn new(params: TpeParams, edges_name: impl Into<String>) -> Self {
        Self { opt: TpeOptimizer::new(params), rng: StdRand::new(), edges_name: edges_name.into() }
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for TpeStage
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers,
    EM: EventFirer<BytesInput, S>,
    S: HasCorpus<BytesInput>
        + libafl::common::HasMetadata
        + libafl::HasNamedMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _mgr: &mut EM,
    ) -> Result<(), Error> {
        if !self.opt.window_due() {
            return Ok(());
        }

        // calculate reward: ΔCorpus
        // let cur_corpus = state.corpus().count();
        // let reward = self.opt.take_reward_from_corpus(cur_corpus).unwrap_or(0.0);
        // calculate reward: ΔEdges
        let (cur_cov, _cov_len) = if let Some(meta) =
            state.named_metadata_map().get::<MapFeedbackMetadata<u8>>(&self.edges_name)
        {
            (meta.num_covered_map_indexes, meta.history_map.len())
        } else { (0, 0) };

        // bootstrap TPE
        if self.opt.is_first_window() {
            if !self.opt.has_last_vec() {
                let params = get_factor_params(state);
                let cur9 = get_current_weight_vec(state);
                let v = if cur9.is_empty() {
                    get_v_candidates(state)
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| {
                            let mut t = vec![params.alpha];
                            t.extend(std::iter::repeat(1.0 / 8f64.sqrt()).take(8));
                            t
                        })
                } else {
                    cur9
                };
                self.opt.set_last_vec(&v);
            }

            let last = self.opt.last_vec();
            if last.len() >= 9 {
                let mut p = get_factor_params(state);
                p.alpha = last[0].clamp(0.0, 1.0);
                set_factor_params(state, p);
                apply_v_to_features(state, &last[1..9])?;
            }

            self.opt.set_last_cov(cur_cov);
            self.opt.advance_window();
            self.opt.persist_to_meta(state);
            self.opt.finish_first_window();

            return Ok(());
        }

        let reward = self.opt
            .take_reward_from_coverage(cur_cov)
            .unwrap_or(0.0);

        // record history
        let last = self.opt.last_vec();
        self.opt.observe(&last, reward);

        // generate new weight_vec
        let new_vec = self.opt.suggest(state, &mut self.rng);
        self.opt.set_last_vec(&new_vec);

        // apply weight_vec
        if new_vec.len() >= 9 {
            let mut p = get_factor_params(state);
            p.alpha = new_vec[0].clamp(0.0, 1.0);
            set_factor_params(state, p);
            apply_v_to_features(state, &new_vec[1..9])?;
        }

        // start new window
        self.opt.advance_window();
        self.opt.set_last_cov(cur_cov);
        // store to metadata
        self.opt.persist_to_meta(state);

        {
            let trials_text = self.opt.snapshot_trials_text();
            _mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: "tpe-trials".into(),
                    value: UserStats::new(
                        UserStatsValue::String(trials_text.into()),
                        AggregatorOps::None,
                    ),
                    phantom: core::marker::PhantomData,
                },
            )?;
        }

        // message monitor callback
        {
            let alpha = new_vec.get(0).copied().unwrap_or(f64::NAN);
            let v_norm = if new_vec.len() >= 9 {
                let v = &new_vec[1..9];
                (v.iter().map(|x| x * x).sum::<f64>()).sqrt()
            } else { f64::NAN };

            let trials_len = self.opt.state.read().unwrap().trials.len();
            let corpus_now = state.corpus().count();

            let v_show = if new_vec.len() >= 9 {
                let mut s = String::new();
                for (i, x) in new_vec[..9].iter().enumerate() {
                    if i > 0 { s.push(','); }
                    s.push_str(&format!("{:.2}", x));
                }
                format!("[{}]", s)
            } else { "[]".to_string() };

            let summary = format!(
                "reward=ΔEdges={:.2}, Coverage={:.1}, trials={}, corpus={}, alpha={:.2}, \
                v_norm={:.2}, v0_8={}, bw={:.2}, gamma={:.2}, samples={}, period={:?}",
                reward, cur_cov, trials_len, corpus_now, alpha,
                v_norm, v_show, self.opt.params.bw, self.opt.params.gamma,
                self.opt.params.samples, self.opt.params.period,
            );

            _mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: "tpe-info".into(),
                    value: UserStats::new(UserStatsValue::String(summary.into()), AggregatorOps::None),
                    phantom: core::marker::PhantomData,
                },
            )?;
        }

        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        // restore TPE history from metadata
        self.opt.restore_once(_state);
        
        Ok(get_features_enabled(_state) && get_tpe_satisfied(_state) && self.opt.window_due())
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
