use libafl::{
    schedulers::testcase_score::{TestcaseScore, CorpusPowerTestcaseScore},
    corpus::Testcase,
    state::HasCorpus,
    common::HasMetadata,
    inputs::BytesInput,
    Error,
};
use super::factor::compute_factor;
use crate::feature_sched::get_factor_params;

#[derive(Clone, Debug, Default)]
pub struct FeatureAwareFastScore;

// implenment TestcaseScore 
impl<S> TestcaseScore<BytesInput, S> for FeatureAwareFastScore
where
    S: HasCorpus<BytesInput> + HasMetadata,
{
    fn compute(state: &S, entry: &mut Testcase<BytesInput>) -> Result<f64, Error> {
        // original FAST perf_score
        let base = CorpusPowerTestcaseScore::compute(state, entry)?;

        // get params and calculate factor
        let params = get_factor_params();
        let factor = compute_factor(params, state, entry);

        Ok(base * factor)
    }
}
