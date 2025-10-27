// feature_sched/tpe_stage.rs
use std::time::Instant;
use libafl::{
    stages::Stage, executors::Executor, events::EventFirer,
    inputs::BytesInput, executors::HasObservers, state::HasCorpus,
    observers::ObserversTuple, Error,
};
use libafl::corpus::Corpus;
use libafl::events::Event;
use libafl::monitors::{AggregatorOps, UserStats, UserStatsValue};

use super::tpe::{TpeOptimizer, TpeParams};
use super::{
    get_factor_params, set_factor_params,
    features_map::{apply_v_to_features},
    get_current_weight_vec, V_CANDIDATES,
};
use libafl_bolts::rands::StdRand;

use crate::feature_sched::{get_features_enabled, get_tpe_satisfied};

pub struct TpeStage {
    pub opt: TpeOptimizer,
    rng: StdRand,
}

impl TpeStage {
    pub fn new(params: TpeParams) -> Self {
        Self { opt: TpeOptimizer::new(params), rng: StdRand::new() }
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for TpeStage
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers,
    EM: EventFirer<BytesInput, S>,
    S: HasCorpus<BytesInput> + libafl::common::HasMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _mgr: &mut EM,
    ) -> Result<(), Error> {
        // init weight_vec = [alpha, v]
        {
            let params = get_factor_params(state);
            let mut v = vec![params.alpha];
            let cur = get_current_weight_vec(state);
            if cur.is_empty() {
                // use V_CANDIDATES[0] as default
                let cand = V_CANDIDATES.read().unwrap();
                if let Some(first) = cand.first() {
                    v.extend_from_slice(&first[..]);
                }
            } else {
                v.extend_from_slice(&cur[..]);
            }
            self.opt.init_vec_if_empty(&v);
        }

        // calculate reward: ΔCorpus
        let cur_corpus = state.corpus().count();
        let reward = self.opt.take_reward_from_corpus(cur_corpus).unwrap_or(0.0);

        // record history
        let last = self.opt.last_vec();
        self.opt.observe(&last, reward);

        // generate new weight_vec
        let new_vec = self.opt.suggest(&mut self.rng);
        self.opt.set_last_vec(&new_vec);

        // apply [alpha + v]
        if new_vec.len() >= 9 {
            let mut params = get_factor_params(state);
            params.alpha = new_vec[0].clamp(0.0, 1.0);
            set_factor_params(state, params);

            let v = &new_vec[1..9]; // 8 dim
            apply_v_to_features(state, v)?;
        }

        // mark end of window
        self.opt.mark_tick();

        // store to metadata
        self.opt.persist_to_meta(state);

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
                for (i, x) in new_vec[1..9].iter().enumerate() {
                    if i > 0 { s.push(','); }
                    s.push_str(&format!("{:.2}", x));
                }
                format!("[{}]", s)
            } else { "[]".to_string() };

            let summary = format!(
                "[TPE] reward=ΔCorpus={:.2}, trials={}, corpus={}, alpha={:.2}, \
                v_norm={:.2}, v8={}, bw={:.2}, gamma={:.2}, samples={}, period={:?}",
                reward, trials_len, corpus_now, alpha,
                v_norm, v_show, self.opt.params.bw, self.opt.params.gamma,
                self.opt.params.samples, self.opt.params.period
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
        self.opt.restore_from_meta(_state);

        Ok(get_features_enabled(_state) && get_tpe_satisfied(_state) && self.opt.should_tick())
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
