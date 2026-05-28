use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use libafl::common::HasMetadata;
use libafl::Error;
use libafl_bolts::current_time;
use serde::Serialize;

use super::mask_selection::mask_to_bitstring;
use super::metadata::{
    ExploreCreditEntry, ExploreCreditHistoryMeta, ExploreCreditMeta, FeatureSpec,
    RuntimeCreditEntry, RuntimeCreditHistoryMeta, RuntimeCreditMeta, RuntimeDataExportMeta,
    TpeHistoryMeta, TpeInitSource, TpeIterationMeta, TpePhase, VecMaskMode, VecMaskRuntimeMeta,
};
use super::{get_active_feature_names, get_schema_features, get_schema_version};

const RUNTIME_DATA_EXPORT_INTERVAL_SECS: u64 = 30;

#[derive(Serialize)]
pub struct RuntimeDataFile {
    pub schema_version: u64,
    pub schema_features: Vec<FeatureSpec>,
    pub mask: RuntimeMaskExport,
    pub initialization: RuntimeInitializationExport,
    pub explore: ExploreCreditExport,
    pub runtime: RuntimeCreditExport,
    pub tpe: TpeExport,
}

#[derive(Serialize)]
pub struct RuntimeMaskExport {
    pub mode: VecMaskMode,
    pub credit_top_k: usize,
    pub requested_explicit_mask: Option<String>,
    pub mask_committed: bool,
    pub effective_mask: String,
    pub selected_feature_names: Vec<String>,
    pub selected_schema_indices: Vec<usize>,
    pub positive_credit_count: usize,
    pub positive_credit_sum: f64,
    pub fallback_reason: Option<String>,
}

#[derive(Serialize)]
pub struct RuntimeInitializationExport {
    pub tpe_init_committed: bool,
    pub source: Option<TpeInitSource>,
    pub candidate_file_path: Option<String>,
    pub candidate_file_loaded: bool,
    pub explore_credits_full: Vec<f64>,
    pub explore_credits_active: Vec<f64>,
    pub normalized_credit_init_v: Vec<f64>,
}

#[derive(Serialize)]
pub struct ExploreCreditExport {
    pub coordinate_feature_names: Vec<String>,
    pub cumulative: ExploreCreditMeta,
    pub history: Vec<ExploreCreditEntry>,
}

#[derive(Serialize)]
pub struct RuntimeCreditExport {
    pub coordinate_feature_names: Vec<String>,
    pub cumulative: RuntimeCreditMeta,
    pub history: Vec<RuntimeCreditEntry>,
}

#[derive(Serialize)]
pub struct TpeExport {
    pub coordinate_feature_names: Vec<String>,
    pub history: TpeHistoryMeta,
    pub phase: TpePhase,
}

fn explore_coordinate_feature_names<S: HasMetadata>(
    state: &S,
    mask_meta: &VecMaskRuntimeMeta,
) -> Vec<String> {
    match mask_meta.mode {
        VecMaskMode::Full | VecMaskMode::AutoCredit => get_schema_features(state)
            .into_iter()
            .map(|feature| feature.name)
            .collect(),
        VecMaskMode::Explicit => {
            if !mask_meta.selected_feature_names.is_empty() {
                mask_meta.selected_feature_names.clone()
            } else {
                get_active_feature_names(state)
            }
        }
    }
}

fn build_runtime_data<S: HasMetadata>(state: &S) -> RuntimeDataFile {
    let mask_meta = state
        .metadata_map()
        .get::<VecMaskRuntimeMeta>()
        .cloned()
        .unwrap_or_default();
    let tpe_iter = state
        .metadata_map()
        .get::<TpeIterationMeta>()
        .cloned()
        .unwrap_or_default();

    let active_names = get_active_feature_names(state);
    RuntimeDataFile {
        schema_version: get_schema_version(state),
        schema_features: get_schema_features(state),
        mask: RuntimeMaskExport {
            mode: mask_meta.mode,
            credit_top_k: mask_meta.credit_top_k,
            requested_explicit_mask: mask_meta
                .requested_explicit_mask
                .as_ref()
                .map(|mask| mask_to_bitstring(mask)),
            mask_committed: mask_meta.mask_committed,
            effective_mask: mask_to_bitstring(&mask_meta.effective_mask),
            selected_feature_names: mask_meta.selected_feature_names.clone(),
            selected_schema_indices: mask_meta.selected_schema_indices.clone(),
            positive_credit_count: mask_meta.positive_credit_count,
            positive_credit_sum: mask_meta.positive_credit_sum,
            fallback_reason: mask_meta.fallback_reason.clone(),
        },
        initialization: RuntimeInitializationExport {
            tpe_init_committed: mask_meta.tpe_init_committed,
            source: mask_meta.tpe_init_source.clone(),
            candidate_file_path: mask_meta.candidate_file_path.clone(),
            candidate_file_loaded: mask_meta.candidate_file_loaded,
            explore_credits_full: mask_meta.explore_credits_full.clone(),
            explore_credits_active: mask_meta.explore_credits_active.clone(),
            normalized_credit_init_v: mask_meta.normalized_credit_init_v.clone(),
        },
        explore: ExploreCreditExport {
            coordinate_feature_names: explore_coordinate_feature_names(state, &mask_meta),
            cumulative: state
                .metadata_map()
                .get::<ExploreCreditMeta>()
                .cloned()
                .unwrap_or_default(),
            history: state
                .metadata_map()
                .get::<ExploreCreditHistoryMeta>()
                .map(|meta| meta.entries.clone())
                .unwrap_or_default(),
        },
        runtime: RuntimeCreditExport {
            coordinate_feature_names: active_names.clone(),
            cumulative: state
                .metadata_map()
                .get::<RuntimeCreditMeta>()
                .cloned()
                .unwrap_or_default(),
            history: state
                .metadata_map()
                .get::<RuntimeCreditHistoryMeta>()
                .map(|meta| meta.entries.clone())
                .unwrap_or_default(),
        },
        tpe: TpeExport {
            coordinate_feature_names: active_names,
            history: state
                .metadata_map()
                .get::<TpeHistoryMeta>()
                .cloned()
                .unwrap_or_default(),
            phase: tpe_iter.phase,
        },
    }
}

fn write_atomic(path: PathBuf, data: &RuntimeDataFile) -> Result<(), Error> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut file = File::create(&tmp_path)?;
        serde_json::to_writer_pretty(&mut file, data)
            .map_err(|err| Error::serialize(err.to_string()))?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

pub fn maybe_export_runtime_data<S: HasMetadata>(state: &mut S, force: bool) -> Result<(), Error> {
    let now = current_time().as_millis() as u64;
    let export_meta = state
        .metadata_map()
        .get::<RuntimeDataExportMeta>()
        .cloned()
        .unwrap_or_default();
    if export_meta.output_path.is_empty() {
        return Ok(());
    }
    if !force
        && export_meta.last_export_ms != 0
        && now.saturating_sub(export_meta.last_export_ms)
            < RUNTIME_DATA_EXPORT_INTERVAL_SECS.saturating_mul(1000)
    {
        return Ok(());
    }

    let output_path = PathBuf::from(export_meta.output_path.clone());
    let data = build_runtime_data(state);
    write_atomic(output_path, &data)?;

    let meta = state
        .metadata_map_mut()
        .get_or_insert_with::<RuntimeDataExportMeta>(Default::default);
    meta.last_export_ms = now;
    Ok(())
}
