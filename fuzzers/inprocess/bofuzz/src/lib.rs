//! BOFuzz: a singlethreaded libfuzzer-like fuzzer with static-feature scheduling.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::{cell::RefCell, time::Duration};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
};

use clap::{parser::ValueSource, Arg, Command};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    mutators::{
        havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, StdMOptMutator,
        StdScheduledMutator, Tokens,
    },
    observers::map::StdMapObserver,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, StdMutationalStage,
        TracingStage,
    },
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    current_time,
    os::dup2,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSlice,
};
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl_targets::autotokens;
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver,
};
#[cfg(unix)]
use nix::unistd::dup;
use serde::Deserialize;

mod feature_sched;
use crate::feature_sched::{
    features_map::{
        compute_active_features, load_and_align_features_map, load_and_validate_feature_map,
        load_and_validate_schema, parse_vec_mask, CandidateFilePolicy,
    },
    get_features_enabled, get_fuzz_start,
    mask_selection::mask_to_bitstring,
    runtime_data::maybe_export_runtime_data,
    set_alpha_init, set_explore_time, set_factor_params, set_feat_exists, set_feat_mode,
    set_fuzz_start, set_schema_info, set_tpe_period, validate_committed_vector_dimensions,
    FactorParams, FeaturesAccountingStage, FeaturesMapMeta, FeaturesMatrixMeta,
    FrontierCreditFeedback, RuntimeDataExportMeta, SancovAcfgMeta, SancovIndexFeedback,
    TpeIterationMeta, VecMaskMode, VecMaskRuntimeMeta, WeightComputeMode, WeightComputeModeMeta,
};
mod custom_monitor;
use crate::custom_monitor::CustomMonitor;

use crate::feature_sched::{get_tpe_period, TpeParams, TpeStage};

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
extern "C" {
    static __start___sancov_cntrs: u8;
    static __stop___sancov_cntrs: u8;
    static __start___sancov_pcs: usize;
    static __stop___sancov_pcs: usize;
}

#[derive(Clone, Debug)]
struct BofuzzArgs {
    factor_params: FactorParams,
    feat_mode: u8,
    explore_time_secs: u64,
    tpe_period_secs: u64,
    weight_compute_mode: WeightComputeMode,
    tpe_samples: usize,
    tpe_gamma: f64,
    tpe_bw: f64,
    trials_threshold: usize,
    re_tpe_threshold_secs: u64,
    sancov_acfg_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct VecMaskConfig {
    mode: VecMaskMode,
    explicit_mask: Option<Vec<bool>>,
    credit_top_k: usize,
}

fn vec_mask_mode_label(mode: VecMaskMode) -> &'static str {
    match mode {
        VecMaskMode::Full => "full",
        VecMaskMode::Explicit => "explicit",
        VecMaskMode::AutoCredit => "auto-credit",
    }
}

fn selected_schema_indices(mask: &[bool]) -> Vec<usize> {
    mask.iter()
        .enumerate()
        .filter_map(|(idx, enabled)| enabled.then_some(idx))
        .collect()
}

fn resolve_vec_mask_config(
    raw_mask: Option<&str>,
    credit_top_k: usize,
    schema_dim: usize,
) -> Result<VecMaskConfig, String> {
    match raw_mask {
        Some(mask) if mask.trim() == "auto-credit" => {
            if credit_top_k == 0 || credit_top_k > schema_dim {
                return Err(format!(
                    "BOFuzz auto-credit error: --credit-top-k must be in 1..={} when --vec-mask auto-credit is selected",
                    schema_dim
                ));
            }
            Ok(VecMaskConfig {
                mode: VecMaskMode::AutoCredit,
                explicit_mask: None,
                credit_top_k,
            })
        }
        Some(mask) => Ok(VecMaskConfig {
            mode: VecMaskMode::Explicit,
            explicit_mask: Some(parse_vec_mask(mask, schema_dim)?),
            credit_top_k,
        }),
        None => Ok(VecMaskConfig {
            mode: VecMaskMode::Full,
            explicit_mask: None,
            credit_top_k,
        }),
    }
}

fn initialize_vec_mask_state<S: HasMetadata>(
    state: &mut S,
    schema: &feature_sched::FeatureSchemaFile,
    config: &VecMaskConfig,
    is_resumed: bool,
) -> Result<Vec<feature_sched::FeatureSpec>, Error> {
    let schema_dim = schema.features.len();
    let full_mask = vec![true; schema_dim];

    if !is_resumed {
        let effective_mask = match config.mode {
            VecMaskMode::Full => full_mask.clone(),
            VecMaskMode::Explicit => config.explicit_mask.clone().ok_or_else(|| {
                Error::illegal_argument("BOFuzz explicit mask config missing mask".to_string())
            })?,
            VecMaskMode::AutoCredit => full_mask.clone(),
        };
        let active_features = compute_active_features(schema, &effective_mask);
        set_schema_info(
            state,
            schema.schema_version,
            schema.features.clone(),
            effective_mask.clone(),
            active_features.clone(),
        );

        let mut runtime = VecMaskRuntimeMeta {
            mode: config.mode,
            credit_top_k: config.credit_top_k,
            requested_explicit_mask: config.explicit_mask.clone(),
            mask_committed: !matches!(config.mode, VecMaskMode::AutoCredit),
            tpe_init_committed: false,
            effective_mask: effective_mask.clone(),
            selected_feature_names: active_features.iter().map(|f| f.name.clone()).collect(),
            selected_schema_indices: selected_schema_indices(&effective_mask),
            ..Default::default()
        };
        if matches!(config.mode, VecMaskMode::Full) {
            runtime.requested_explicit_mask = None;
        }
        state.add_metadata(runtime);

        match config.mode {
            VecMaskMode::Full => eprintln!(
                "[BOFuzz mask] mode=full status=locked active_dim={} mask={}",
                active_features.len(),
                mask_to_bitstring(&effective_mask)
            ),
            VecMaskMode::Explicit => eprintln!(
                "[BOFuzz mask] mode=explicit status=locked active_dim={} mask={}",
                active_features.len(),
                mask_to_bitstring(&effective_mask)
            ),
            VecMaskMode::AutoCredit => eprintln!(
                "[BOFuzz mask] mode=auto-credit status=explore-full top_k={} explore_dim={} mask={}",
                config.credit_top_k,
                schema_dim,
                mask_to_bitstring(&effective_mask)
            ),
        }
        return Ok(active_features);
    }

    let mut runtime = state
        .metadata_map()
        .get::<VecMaskRuntimeMeta>()
        .cloned()
        .ok_or_else(|| {
            Error::illegal_state(
                "BOFuzz resume error: missing persisted vec-mask runtime metadata".to_string(),
            )
        })?;

    if runtime.mode != config.mode {
        return Err(Error::illegal_state(
            "BOFuzz resume error: vec-mask mode differs from persisted run".to_string(),
        ));
    }

    match config.mode {
        VecMaskMode::Full => {
            if runtime.effective_mask != full_mask {
                return Err(Error::illegal_state(
                    "BOFuzz resume error: full mode persisted mask is not full schema".to_string(),
                ));
            }
        }
        VecMaskMode::Explicit => {
            let requested = config.explicit_mask.clone().ok_or_else(|| {
                Error::illegal_state(
                    "BOFuzz resume error: explicit mode requires CLI vec-mask".to_string(),
                )
            })?;
            if runtime.requested_explicit_mask.as_ref() != Some(&requested)
                || runtime.effective_mask != requested
            {
                return Err(Error::illegal_state(
                    "BOFuzz resume error: explicit vec-mask differs from persisted committed mask"
                        .to_string(),
                ));
            }
        }
        VecMaskMode::AutoCredit => {
            if runtime.credit_top_k != config.credit_top_k {
                return Err(Error::illegal_state(
                    "BOFuzz resume error: auto-credit top_k differs from persisted run".to_string(),
                ));
            }
            if !runtime.mask_committed && runtime.effective_mask != full_mask {
                return Err(Error::illegal_state(
                    "BOFuzz resume error: pending auto-credit run is not in full-schema Explore"
                        .to_string(),
                ));
            }
        }
    }

    let active_features = compute_active_features(schema, &runtime.effective_mask);
    runtime.selected_feature_names = active_features.iter().map(|f| f.name.clone()).collect();
    runtime.selected_schema_indices = selected_schema_indices(&runtime.effective_mask);
    set_schema_info(
        state,
        schema.schema_version,
        schema.features.clone(),
        runtime.effective_mask.clone(),
        active_features.clone(),
    );
    state.add_metadata(runtime.clone());

    if runtime.tpe_init_committed {
        validate_committed_vector_dimensions(state)?;
    }

    let status = match runtime.mode {
        VecMaskMode::Full => "restored-locked",
        VecMaskMode::Explicit => "restored-locked",
        VecMaskMode::AutoCredit if runtime.mask_committed => "restored-committed",
        VecMaskMode::AutoCredit => "restored-pending",
    };
    eprintln!(
        "[BOFuzz mask] mode={} status={} active_dim={} mask={}",
        vec_mask_mode_label(runtime.mode),
        status,
        active_features.len(),
        mask_to_bitstring(&runtime.effective_mask)
    );

    Ok(active_features)
}

fn resolve_bofuzz_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?.to_path_buf();
    for _ in 0..10 {
        let candidate = dir.join("static_analysis/features_schema.json");
        if candidate.exists() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("static_analysis/features_schema.json");
        if candidate.exists() {
            return Some(cwd);
        }
    }
    None
}

fn default_schema_path() -> Option<PathBuf> {
    let root = resolve_bofuzz_root()?;
    Some(root.join("static_analysis/features_schema.json"))
}

fn default_sancov_acfg_path_from_current_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let stem = exe.file_stem()?.to_string_lossy();
    Some(exe_dir.join(format!("{}_sancov_acfg.json", stem)))
}

fn parse_weight_compute_mode(raw: &str) -> Result<WeightComputeMode, String> {
    match raw {
        "frontier" => Ok(WeightComputeMode::Frontier),
        "path" => Ok(WeightComputeMode::Path),
        other => Err(format!(
            "BOFuzz --weight-compute error: expected frontier|path, got {}",
            other
        )),
    }
}

#[derive(Debug, Deserialize)]
struct SancovAcfgFile {
    schema_version: u64,
    kind: String,
    n_sancov_sites: usize,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
}

fn load_sancov_acfg(path: &Path, sancov_sites: usize) -> Result<SancovAcfgMeta, String> {
    let mut f = File::open(path).map_err(|e| {
        format!(
            "BOFuzz sancov ACFG error: cannot open {}: {}",
            path.display(),
            e
        )
    })?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| {
        format!(
            "BOFuzz sancov ACFG error: cannot read {}: {}",
            path.display(),
            e
        )
    })?;
    let file: SancovAcfgFile = serde_json::from_str(&s).map_err(|e| {
        format!(
            "BOFuzz sancov ACFG error: invalid JSON in {}: {}",
            path.display(),
            e
        )
    })?;
    if file.schema_version != 1 || file.kind != "bofuzz-sancov-acfg-v1" {
        return Err(format!(
            "BOFuzz sancov ACFG error: {} has unsupported schema/kind",
            path.display()
        ));
    }
    if file.n_sancov_sites != sancov_sites {
        return Err(format!(
            "BOFuzz sancov ACFG error: n_sancov_sites {} != runtime sancov sites {}",
            file.n_sancov_sites, sancov_sites
        ));
    }
    if file.successors.len() != file.n_sancov_sites {
        return Err("BOFuzz sancov ACFG error: successors length mismatch".to_string());
    }
    if file.predecessors.len() != file.n_sancov_sites {
        return Err("BOFuzz sancov ACFG error: predecessors length mismatch".to_string());
    }
    for (kind, lists) in [
        ("successors", &file.successors),
        ("predecessors", &file.predecessors),
    ] {
        for (i, xs) in lists.iter().enumerate() {
            for &node in xs {
                if node >= file.n_sancov_sites {
                    return Err(format!(
                        "BOFuzz sancov ACFG error: {}[{}] contains out-of-range node {}",
                        kind, i, node
                    ));
                }
            }
        }
    }
    Ok(SancovAcfgMeta {
        iteration: 0,
        n_sancov_sites: file.n_sancov_sites,
        successors: file.successors,
        predecessors: file.predecessors,
    })
}

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub extern "C" fn libafl_main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("BOFuzz team")
        .about("BOFuzz: LibAFL-based fuzzer with static-feature scheduling")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("tokens")
                .short('x')
                .long("tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("logfile")
                .short('l')
                .long("logfile")
                .help("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("1200"),
        )
        .arg(
            Arg::new("features-schema")
                .long("features-schema")
                .help("Path to features_schema.json (default: BOFuzz/static_analysis/features_schema.json)")
        )
        .arg(
            Arg::new("features")
              .long("features-map")
              .help("Path to {target}_features_map.json")
        )
        .arg(
            Arg::new("vec-mask")
                .long("vec-mask")
                .help("Feature mask aligned to features_schema.json order, or 'auto-credit'. Accepts '[1,0,...]', '1,0,...', bitstring '1010...', or 'auto-credit'.")
        )
        .arg(
            Arg::new("credit-top-k")
                .long("credit-top-k")
                .value_parser(clap::value_parser!(usize))
                .default_value("8")
                .help("Maximum number of positive frontier-credit-ranked features selected when --vec-mask auto-credit is used; default: 8")
        )
        .arg(
            Arg::new("alpha")
                .long("alpha")
                .default_value("0.85")
                .help("fixed feature factor blend alpha")
        )
        .arg(
            Arg::new("beta")
                .long("beta")
                .default_value("0.6")
                .help("exp(<beta>)")
        )
        .arg(
            Arg::new("gmin")
                .long("gmin")
                .default_value("0.5")
                .help("factor range: (<gmin>, gmax)")
        )
        .arg(
            Arg::new("gmax")
                .long("gmax")
                .default_value("2.0")
                .help("factor range: (gmin, <gmax>)")
        )
        .arg(
            Arg::new("tanh")
                .long("tanh")
                .action(clap::ArgAction::SetTrue)
                .help("use tanh mapping instead of exp")
        )
        .arg(
            Arg::new("feat-mode")
                .long("feat-mode")
                .value_parser(clap::value_parser!(u8).range(0..=3))
                .default_value("1")
                .help("0: off, 1: weight scheduling only, 2: power scheduling only, 3: both")
        )
        .arg(
            Arg::new("weight-compute")
                .long("weight-compute")
                .value_parser(["frontier", "path"])
                .default_value("frontier")
                .help("Feature corpus weight computation mode")
        )
        .arg(
            Arg::new("explore-time-secs")
                .long("explore-time-secs")
                .value_parser(clap::value_parser!(u64))
                .default_value("43200")
                .help("Explore time before enabling features, in seconds (default: 43200 = 12 hours)")
        )
        .arg(
            Arg::new("tpe-period-secs")
                .long("tpe-period-secs")
                .value_parser(clap::value_parser!(u64))
                .default_value("600")
                .help("TPE learning period per iteration, in seconds (default: 600 = 10 minutes)")
        )
        .arg(
            Arg::new("tpe-samples")
                .long("tpe-samples")
                .value_parser(clap::value_parser!(usize))
                .default_value("16")
                .help("Number of KDE samples for initial and inverse TPE candidate pools")
        )
        .arg(
            Arg::new("tpe-gamma")
                .long("tpe-gamma")
                .value_parser(clap::value_parser!(f64))
                .default_value("0.15")
                .help("TPE good-set split ratio")
        )
        .arg(
            Arg::new("tpe-bw")
                .long("tpe-bw")
                .value_parser(clap::value_parser!(f64))
                .default_value("0.05")
                .help("Logit-space KDE bandwidth")
        )
        .arg(
            Arg::new("trials-threshold")
                .long("trials-threshold")
                .value_parser(clap::value_parser!(usize))
                .default_value("5")
                .help("Positive-reward trials required before KDE TPE")
        )
        .arg(
            Arg::new("re-tpe-threshold-secs")
                .long("re-tpe-threshold-secs")
                .value_parser(clap::value_parser!(u64))
                .default_value("3600")
                .help("LockedBest no-new-edge interval before inverse re-TPE")
        )
        .arg(
            Arg::new("sancov-acfg")
                .long("sancov-acfg")
                .help("Path to {target}_sancov_acfg.json")
        )
        .arg(Arg::new("remaining"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    if let Some(filenames) = res.get_many::<String>("remaining") {
        let filenames: Vec<&str> = filenames.map(String::as_str).collect();
        if !filenames.is_empty() {
            run_testcases(&filenames);
            return;
        }
    }

    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let output_root = out_dir.clone();
    let runtime_data_output_path = output_root.join("runtime_data.json");
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    // --- Step 1: Resolve schema path ---
    let schema_path: PathBuf = if let Some(p) = res.get_one::<String>("features-schema") {
        PathBuf::from(p)
    } else {
        match default_schema_path() {
            Some(p) => p,
            None => {
                eprintln!("BOFuzz feature schema error: missing required file BOFuzz/static_analysis/features_schema.json");
                eprintln!("Provide --features-schema or ensure BOFuzz/static_analysis/features_schema.json exists.");
                process::exit(1);
            }
        }
    };

    // --- Step 2: Load and validate schema ---
    let schema = match load_and_validate_schema(&schema_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };
    let schema_dim = schema.features.len();
    eprintln!(
        "[BOFuzz] schema loaded: version={} features={} path={}",
        schema.schema_version,
        schema_dim,
        schema_path.display()
    );

    // --- Step 3: Resolve --vec-mask mode and --credit-top-k policy ---
    let credit_top_k = *res.get_one::<usize>("credit-top-k").unwrap();
    let vec_mask_config = match resolve_vec_mask_config(
        res.get_one::<String>("vec-mask").map(String::as_str),
        credit_top_k,
        schema_dim,
    ) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };
    if vec_mask_config.mode != VecMaskMode::AutoCredit
        && res.value_source("credit-top-k") == Some(ValueSource::CommandLine)
    {
        eprintln!(
            "[BOFuzz mask] warning: --credit-top-k is ignored unless --vec-mask auto-credit is selected"
        );
    }

    let cli_features_path = res.get_one::<String>("features").map(PathBuf::from);
    let weight_compute_mode = match parse_weight_compute_mode(
        res.get_one::<String>("weight-compute").unwrap().as_str(),
    ) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };
    let params = FactorParams {
        alpha: res.get_one::<String>("alpha").unwrap().parse().unwrap(),
        beta: res.get_one::<String>("beta").unwrap().parse().unwrap(),
        gmin: res.get_one::<String>("gmin").unwrap().parse().unwrap(),
        gmax: res.get_one::<String>("gmax").unwrap().parse().unwrap(),
        use_tanh: res.get_flag("tanh"),
    };

    let bofuzz_args = BofuzzArgs {
        factor_params: params,
        feat_mode: *res.get_one::<u8>("feat-mode").unwrap(),
        explore_time_secs: *res.get_one::<u64>("explore-time-secs").unwrap(),
        tpe_period_secs: *res.get_one::<u64>("tpe-period-secs").unwrap(),
        weight_compute_mode,
        tpe_samples: *res.get_one::<usize>("tpe-samples").unwrap(),
        tpe_gamma: *res.get_one::<f64>("tpe-gamma").unwrap(),
        tpe_bw: *res.get_one::<f64>("tpe-bw").unwrap(),
        trials_threshold: *res.get_one::<usize>("trials-threshold").unwrap(),
        re_tpe_threshold_secs: *res.get_one::<u64>("re-tpe-threshold-secs").unwrap(),
        sancov_acfg_path: res.get_one::<String>("sancov-acfg").map(PathBuf::from),
    };

    fuzz(
        out_dir,
        crashes,
        &in_dir,
        tokens,
        &logfile,
        timeout,
        cli_features_path,
        bofuzz_args,
        schema,
        vec_mask_config,
        runtime_data_output_path,
    )
    .expect("An error occurred while fuzzing");
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn auto_credit_vec_mask_is_accepted() {
        let config = resolve_vec_mask_config(Some("auto-credit"), 8, 16).unwrap();
        assert_eq!(config.mode, VecMaskMode::AutoCredit);
        assert_eq!(config.credit_top_k, 8);
        assert!(config.explicit_mask.is_none());
    }

    #[test]
    fn credit_top_k_defaults_to_eight_when_supplied_as_default() {
        let config = resolve_vec_mask_config(Some("auto-credit"), 8, 16).unwrap();
        assert_eq!(config.credit_top_k, 8);
    }

    #[test]
    fn credit_top_k_rejected_when_zero_in_auto_mode() {
        assert!(resolve_vec_mask_config(Some("auto-credit"), 0, 16).is_err());
    }

    #[test]
    fn credit_top_k_rejected_when_greater_than_schema_dim() {
        assert!(resolve_vec_mask_config(Some("auto-credit"), 17, 16).is_err());
    }

    #[test]
    fn explicit_bitstring_mask_remains_supported() {
        let config = resolve_vec_mask_config(Some("1010"), 8, 4).unwrap();
        assert_eq!(config.mode, VecMaskMode::Explicit);
        assert_eq!(
            config.explicit_mask.unwrap(),
            vec![true, false, true, false]
        );
    }

    #[test]
    fn explicit_comma_mask_remains_supported() {
        let config = resolve_vec_mask_config(Some("1,0,1,0"), 8, 4).unwrap();
        assert_eq!(
            config.explicit_mask.unwrap(),
            vec![true, false, true, false]
        );
    }

    #[test]
    fn explicit_bracketed_mask_remains_supported() {
        let config = resolve_vec_mask_config(Some("[1,0,1,0]"), 8, 4).unwrap();
        assert_eq!(
            config.explicit_mask.unwrap(),
            vec![true, false, true, false]
        );
    }

    #[test]
    fn explicit_all_zero_mask_remains_rejected() {
        assert!(resolve_vec_mask_config(Some("0000"), 8, 4).is_err());
    }

    #[test]
    fn no_vec_mask_resolves_to_full_mode() {
        let config = resolve_vec_mask_config(None, 8, 16).unwrap();
        assert_eq!(config.mode, VecMaskMode::Full);
        assert!(config.explicit_mask.is_none());
    }
}

fn run_testcases(filenames: &[&str]) {
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    println!(
        "You are not fuzzing, just executing {} testcases",
        filenames.len()
    );
    for fname in filenames {
        println!("Executing {fname}");

        let mut file = File::open(fname).expect("No file found");
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).expect("Buffer overflow");

        unsafe {
            libfuzzer_test_one_input(&buffer);
        }
    }
}

/// The actual fuzzer
#[expect(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: &PathBuf,
    tokenfile: Option<PathBuf>,
    logfile: &PathBuf,
    timeout: Duration,
    cli_features_path: Option<PathBuf>,
    bofuzz_args: BofuzzArgs,
    schema: feature_sched::FeatureSchemaFile,
    vec_mask_config: VecMaskConfig,
    runtime_data_output_path: PathBuf,
) -> Result<(), Error> {
    let log = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    let schema_dim = schema.features.len();

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    let monitor = CustomMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{s}").unwrap();
        #[cfg(windows)]
        println!("{s}");
        writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };

    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let (sancov_observer, sancov_sites, cntrs_ptr) = unsafe {
        let start = &__start___sancov_cntrs as *const u8 as usize;
        let stop = &__stop___sancov_cntrs as *const u8 as usize;
        let sancov_sites = stop
            .checked_sub(start)
            .expect("sancov cntrs pointers inverted?");
        let cntrs_ptr = start as *mut u8;
        let pcs_start = &__start___sancov_pcs as *const usize as usize;
        let pcs_stop = &__stop___sancov_pcs as *const usize as usize;
        let word_len = core::mem::size_of::<usize>();
        let pcs_sites = (pcs_stop - pcs_start) / (2 * word_len);
        assert_eq!(
            sancov_sites, pcs_sites,
            "sancov cntrs/pcs size mismatch: {sancov_sites} vs {pcs_sites}"
        );

        let obs = StdMapObserver::<u8, false>::from_mut_ptr("sancov", cntrs_ptr, sancov_sites);
        (obs, sancov_sites, cntrs_ptr)
    };
    let sancov_handle = sancov_observer.handle();

    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::new(&edges_observer);
    let sancov_idx_fb = SancovIndexFeedback::new(&sancov_observer);
    let frontier_credit_fb = FrontierCreditFeedback::new();

    let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = feedback_or!(
        map_feedback,
        TimeFeedback::new(&time_observer),
        sancov_idx_fb,
        frontier_credit_fb
    );

    let mut objective = CrashFeedback::new();

    let is_resumed = state.is_some();
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::new(),
            InMemoryOnDiskCorpus::new(corpus_dir.clone()).unwrap(),
            OnDiskCorpus::new(objective_dir.clone()).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    // --- Runtime startup order (Section 4.6) ---

    let active_features =
        initialize_vec_mask_state(&mut state, &schema, &vec_mask_config, is_resumed)?;
    let active_dim = active_features.len();
    let active_names: Vec<String> = active_features.iter().map(|f| f.name.clone()).collect();
    state.add_metadata(RuntimeDataExportMeta {
        output_path: runtime_data_output_path.display().to_string(),
        last_export_ms: 0,
    });

    eprintln!(
        "[BOFuzz features] schema={} schema_dim={} active_dim={} mask={} active=[{}]",
        schema.schema_version,
        schema_dim,
        active_dim,
        mask_to_bitstring(&feature_sched::get_vec_mask(&state)),
        active_features
            .iter()
            .map(|f| format!("{}:{}", f.id, f.name))
            .collect::<Vec<_>>()
            .join(",")
    );

    // 2. Set factor params
    set_alpha_init(&mut state, bofuzz_args.factor_params.alpha);
    set_factor_params(&mut state, bofuzz_args.factor_params.clone());
    eprintln!(
        "[BOFuzz params] alpha={:.3}, beta={:.3}, gmin={:.3}, gmax={:.3}, use_tanh={}",
        bofuzz_args.factor_params.alpha,
        bofuzz_args.factor_params.beta,
        bofuzz_args.factor_params.gmin,
        bofuzz_args.factor_params.gmax,
        bofuzz_args.factor_params.use_tanh
    );

    // 3. Default features path: same directory as binary, named {target}_features_map.json
    fn default_features_path() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));
        let stem = exe.file_stem()?.to_string_lossy();
        Some(exe_dir.join(format!("{}_features_map.json", stem)))
    }

    let chosen_path = if let Some(p) = cli_features_path {
        Some(p)
    } else {
        default_features_path()
    };
    let chosen_path = chosen_path.and_then(|p| if p.exists() { Some(p) } else { None });

    // 4. Validate feature map against schema if present
    let mut pending_feats: Option<Vec<f64>> = None;
    let mut pending_matrix: Option<std::collections::HashMap<String, Vec<f64>>> = None;
    let has_feats;

    if let Some(p) = chosen_path.as_ref() {
        // Validate and canonicalize the feature map in one pass
        match load_and_validate_feature_map(p, &schema, sancov_sites) {
            Ok(canonical_map) => {
                // Use the canonicalized map directly (no re-reading raw JSON)
                let runtime_mask = state
                    .metadata_map()
                    .get::<VecMaskRuntimeMeta>()
                    .cloned()
                    .unwrap_or_default();
                let candidate_policy = if runtime_mask.mode == VecMaskMode::AutoCredit {
                    CandidateFilePolicy::IgnoreExternalFile
                } else {
                    CandidateFilePolicy::AllowExternalFile
                };
                let restored_current_v = if is_resumed {
                    feature_sched::get_current_weight_vec(&state)
                } else {
                    Vec::new()
                };
                match load_and_align_features_map(
                    &mut state,
                    &canonical_map,
                    sancov_sites,
                    active_dim,
                    &active_names,
                    p,
                    candidate_policy,
                    vec_mask_mode_label(runtime_mask.mode),
                ) {
                    Ok(load_result) => {
                        eprintln!("[BOFuzz] using features map: {}", p.display());
                        if let Some(mask_meta) =
                            state.metadata_map_mut().get_mut::<VecMaskRuntimeMeta>()
                        {
                            if !is_resumed || !mask_meta.tpe_init_committed {
                                let candidate_path = load_result
                                    .candidate_status
                                    .path
                                    .as_ref()
                                    .map(|path| path.display().to_string());
                                if !is_resumed
                                    || load_result.candidate_status.loaded
                                    || mask_meta.candidate_file_path.is_none()
                                {
                                    mask_meta.candidate_file_path = candidate_path;
                                }
                                if mask_meta.mode == VecMaskMode::AutoCredit {
                                    mask_meta.candidate_file_loaded = false;
                                } else if !is_resumed || load_result.candidate_status.loaded {
                                    mask_meta.candidate_file_loaded =
                                        load_result.candidate_status.loaded;
                                }
                            }
                        }
                        if is_resumed && !restored_current_v.is_empty() {
                            feature_sched::set_current_weight_vec(
                                &mut state,
                                restored_current_v.clone(),
                            );
                        }
                        pending_feats = Some(load_result.feats);
                        pending_matrix = Some(load_result.active_matrix);
                        has_feats = true;
                    }
                    Err(e) => {
                        eprintln!("[BOFuzz] feature-map load failed: {}. Aborting.", e);
                        process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                eprintln!("[BOFuzz] Feature map is present but invalid — aborting.");
                process::exit(1);
            }
        }
    } else {
        eprintln!("warning: BOFuzz features_map not found; feature scheduling disabled, continue cold fuzzing.");
        has_feats = false;
    }

    if !is_resumed || get_fuzz_start(&state) == 0 {
        set_fuzz_start(&mut state);
    }
    eprintln!(
        "[BOFuzz params] fuzz start time: {} s",
        get_fuzz_start(&state) / 1000
    );

    if let Some(feats) = pending_feats.take() {
        state.add_metadata(FeaturesMapMeta { feats });
    }
    if let Some(matrix) = pending_matrix.take() {
        state.add_metadata(FeaturesMatrixMeta {
            matrix,
            sites: sancov_sites,
        });
    }
    set_feat_exists(&mut state, has_feats);
    state.add_metadata(WeightComputeModeMeta {
        mode: bofuzz_args.weight_compute_mode,
    });
    if state.metadata_map().get::<TpeIterationMeta>().is_none() {
        state.add_metadata(TpeIterationMeta::default());
    }

    if has_feats
        && bofuzz_args.feat_mode != 0
        && bofuzz_args.weight_compute_mode == WeightComputeMode::Frontier
    {
        let acfg_path = bofuzz_args
            .sancov_acfg_path
            .clone()
            .or_else(default_sancov_acfg_path_from_current_exe)
            .ok_or_else(|| {
                Error::illegal_argument(
                    "BOFuzz sancov ACFG error: cannot derive default path".to_string(),
                )
            })?;
        match load_sancov_acfg(&acfg_path, sancov_sites) {
            Ok(meta) => {
                eprintln!("[BOFuzz] using sancov ACFG: {}", acfg_path.display());
                state.add_metadata(meta);
            }
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        }
    }

    set_feat_mode(&mut state, bofuzz_args.feat_mode);
    eprintln!("[BOFuzz params] feat_mode={}", bofuzz_args.feat_mode);

    set_explore_time(&mut state, bofuzz_args.explore_time_secs);

    set_tpe_period(&mut state, bofuzz_args.tpe_period_secs);
    eprintln!(
        "[BOFuzz params] explore_time_secs={}, tpe_period_secs={}",
        bofuzz_args.explore_time_secs, bofuzz_args.tpe_period_secs
    );

    eprintln!(
        "[BOFuzz params] features_enabled={}, features_map={}, active_dim={}, schema_dim={}",
        get_features_enabled(&state),
        chosen_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".into()),
        active_dim,
        schema_dim,
    );
    eprintln!(
        "[BOFuzz params] timeout_ms={}, corpus_dir={}, crashes_dir={}, seeds_dir={}, tokens={}",
        timeout.as_millis(),
        corpus_dir.display(),
        objective_dir.display(),
        seed_dir.display(),
        tokenfile
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".into())
    );
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    eprintln!("[BOFuzz params] sancov_sites={}", sancov_sites);

    println!("Let's fuzz :)");

    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::fast()),
        ),
    );

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        unsafe {
            core::ptr::write_bytes(cntrs_ptr, 0, sancov_sites);
        }

        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    };

    let mut tracing_harness = harness;

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, sancov_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let tracing = TracingStage::new(InProcessExecutor::with_timeout(
        &mut tracing_harness,
        tuple_list!(cmplog_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout * 10,
    )?);

    let feat_stage = FeaturesAccountingStage::new(sancov_handle.clone());

    let edges_name = "edges".to_string();
    let tpe_stage = {
        let p = TpeParams {
            period: Duration::from_secs(get_tpe_period(&state)),
            samples: bofuzz_args.tpe_samples,
            gamma: bofuzz_args.tpe_gamma,
            bw: bofuzz_args.tpe_bw,
            trials_threshold: bofuzz_args.trials_threshold,
            re_tpe_threshold: Duration::from_secs(bofuzz_args.re_tpe_threshold_secs),
        };
        TpeStage::new(p, edges_name.clone())
    };

    let mut stages = tuple_list!(calibration, tracing, feat_stage, i2s, power, tpe_stage);

    if state.metadata_map().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = tokenfile {
            toks.add_from_file(tokenfile)?;
        }
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            toks += autotokens()?;
        }

        if !toks.is_empty() {
            state.add_metadata(toks);
        }
    }

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                std::slice::from_ref(seed_dir),
            )
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        if std::env::var("LIBAFL_FUZZBENCH_DEBUG").is_err() {
            dup2(null_fd, io::stderr().as_raw_fd())?;
        }
    }
    log.replace(OpenOptions::new().append(true).create(true).open(logfile)?);

    let fuzz_result = fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr);
    let export_result = maybe_export_runtime_data(&mut state, true);
    fuzz_result?;
    export_result?;

    Ok(())
}
