//! A singlethreaded libfuzzer-like fuzzer that can auto-restart.
/*
lib.rs: libfun fuzzer main entry
*/
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

use clap::{Arg, Command};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, StdMOptMutator,
        StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, TimeObserver, HitcountsMapObserver},
    observers::map::StdMapObserver,
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage, StdMutationalStage, TracingStage, power::StdPowerMutationalStage,
    },
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    current_time,
    os::dup2,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge, Handled},
    AsSlice,
};
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl_targets::autotokens;
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, CmpLogObserver, std_edges_map_observer,
};
#[cfg(unix)]
use nix::unistd::dup;

// libfun mod
mod feature_sched;
use crate::feature_sched::{
    features_map::load_and_align_features_map,
    FeaturesAccountingStage, FeaturesMapMeta, FactorParams, FeaturesMatrixMeta, SancovIndexFeedback,
    get_features_enabled, set_fuzz_start, get_fuzz_start,
    set_factor_params, set_feat_exists,
    set_explore_time, set_tpe_period,
    set_tpe_satisfied, set_current_weight_vec,
    set_feat_mode, set_alpha_init,
};
mod custom_monitor;
use crate::custom_monitor::CustomMonitor;

use crate::feature_sched::{ TpeStage, TpeParams, get_tpe_period };

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
extern "C" {
    // fn __sanitizer_cov_reset_counters(); // reset map for each testcase | not linked 
    // 8-bit counters
    static __start___sancov_cntrs: u8;
    static __stop___sancov_cntrs: u8;
    // pc-table
    static __start___sancov_pcs: usize;
    static __stop___sancov_pcs: usize;
}

// feature/tpe parameters
#[derive(Clone, Debug)]
struct FunArgs {
    factor_params: FactorParams,
    feat_mode: u8,
    explore_time_secs: u64,
    tpe_period_secs: u64,
}

// format vector printing
fn fmt_vec_short(v: &[f64], maxn: usize) -> String {
    let n = v.len();
    let take = n.min(maxn);
    let mut s = v[..take].iter()
        .map(|x| format!("{:.3}", x))
        .collect::<Vec<_>>()
        .join(",");
    if n > take { s.push_str(",..."); }
    format!("[{}] (len={})", s, n)
}

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer for Fuzzbench")
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
            Arg::new("features")
              .long("features-map")
              .help("Path to {target}_features_map.json")
          )
        .arg(
            Arg::new("alpha")
                .long("alpha")
                .default_value("0.2")
                .help("the <alpha> * features_factor")
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
                .default_value("3.0")
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
                .default_value("0")
                .help("0: off, 1: weight only, 2: power only, 3: both")
            )
        .arg(
            Arg::new("explore-time")
                .long("explore-time")
                .value_parser(clap::value_parser!(u64))
                .default_value("12")
                .help("explore time set for explore stage, default is 12 hours")
            )
        .arg(
            Arg::new("tpe-period")
                .long("tpe-period")
                .value_parser(clap::value_parser!(u64))
                .default_value("10")
                .help("TPE period set for TPE learning period each iteration, default is 10 min")
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

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
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

    let cli_features_path = res.get_one::<String>("features").map(PathBuf::from);
    let params = FactorParams {
        alpha: res.get_one::<String>("alpha").unwrap().parse().unwrap(),
        beta:  res.get_one::<String>("beta").unwrap().parse().unwrap(),
        gmin:  res.get_one::<String>("gmin").unwrap().parse().unwrap(),
        gmax:  res.get_one::<String>("gmax").unwrap().parse().unwrap(),
        use_tanh: res.get_flag("tanh"),
    };

    let fun_args = FunArgs {
        factor_params: params,
        feat_mode: *res.get_one::<u8>("feat-mode").unwrap(),
        explore_time_secs: *res.get_one::<u64>("explore-time").unwrap(),
        tpe_period_secs: *res.get_one::<u64>("tpe-period").unwrap(),
    };

    fuzz(out_dir, crashes, &in_dir, tokens, &logfile, timeout, cli_features_path, fun_args)
        .expect("An error occurred while fuzzing");
}

fn run_testcases(filenames: &[&str]) {
    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
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
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: &PathBuf,
    tokenfile: Option<PathBuf>,
    logfile: &PathBuf,
    timeout: Duration,
    cli_features_path: Option<PathBuf>,
    fun_args: FunArgs,
) -> Result<(), Error> {
    let log = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    // let monitor = SimpleMonitor::new(|s| {
    //     #[cfg(unix)]
    //     writeln!(&mut stdout_cpy, "{s}").unwrap();
    //     #[cfg(windows)]
    //     println!("{s}");
    //     writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
    // });
    let monitor = CustomMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{s}").unwrap();
        #[cfg(windows)]
        println!("{s}");
        writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
    });

    // We need a shared map to store our state before a crash.
    // This way, we are able to continue fuzzing afterwards.
    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
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

    // Create an observation channel using the coverage map
    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();
    // in libfun we use sancov cntrs_ptr to align indices with static features
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let (sancov_observer, sancov_sites, cntrs_ptr) = unsafe {
        let start = &__start___sancov_cntrs as *const u8 as usize;
        let stop = &__stop___sancov_cntrs as *const u8 as usize;
        let sancov_sites = stop.checked_sub(start).expect("sancov cntrs pointers inverted?");
        let cntrs_ptr = start as *mut u8;
        // check the length of sites (8-bit counters) and pc-table are consistent
        let pcs_start = &__start___sancov_pcs as *const usize as usize;
        let pcs_stop = &__stop___sancov_pcs as *const usize as usize;
        let word_len = core::mem::size_of::<usize>();
        let pcs_sites = (pcs_stop - pcs_start) / (2 * word_len);
        assert_eq!(sancov_sites, pcs_sites, "sancov cntrs/pcs size mismatch: {sancov_sites} vs {pcs_sites}");
    
        // set 8-bit counters observer
        let obs = StdMapObserver::<u8, false>::from_mut_ptr("sancov", cntrs_ptr, sancov_sites);
        (obs, sancov_sites, cntrs_ptr)
    };
    let sancov_handle = sancov_observer.handle();

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::new(&edges_observer);
    let sancov_idx_fb = SancovIndexFeedback::new(&sancov_observer);

    let calibration = CalibrationStage::new(&map_feedback);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer),
        sancov_idx_fb
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::new(),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new(corpus_dir.clone()).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir.clone()).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    fn default_features_path() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));
        let stem = exe.file_stem()?.to_string_lossy();
        Some(exe_dir.join(format!("{}_features_map.json", stem)))
    }

    // use /path_to/the_same_directory/{target_name}_features_map.json file as default file path
    let chosen_path = if let Some(p) = cli_features_path { Some(p) } else { default_features_path() };
    let chosen_path = chosen_path.and_then(|p| if p.exists() { Some(p) } else { None });

    let mut pending_feats: Option<Vec<f64>> = None;
    let mut pending_matrix: Option<std::collections::HashMap<String, Vec<f64>>> = None;
    let mut has_feats = false;
    if let Some(p) = chosen_path.as_ref() {
        match load_and_align_features_map(&mut state, p, sancov_sites) {
            Ok((feats, matrix_opt)) => {
                eprintln!("[features] using features map: {}", p.display());
                pending_feats = Some(feats);
                pending_matrix = matrix_opt;
                has_feats = true;
            }
            Err(e) => {
                eprintln!("[features] failed to load {}: {e}. Disabling features.", p.display());
                has_feats = false;
            }
        }
    } else {
        eprintln!("[features] no features map provided/found. Disabling features.");
        has_feats = false;
    }

    // Fuzz Start Time record
    set_fuzz_start(&mut state);
    eprintln!("[params] fuzz start time: {} s", get_fuzz_start(&state) / 1000);

    // add features_map to metadata
    if let Some(feats) = pending_feats.take() {
        state.add_metadata(FeaturesMapMeta { feats });
    }
    // add source features_map matrix to metadata
    if let Some(matrix) = pending_matrix.take() {
        state.add_metadata(FeaturesMatrixMeta { matrix, sites: sancov_sites });
    }
    set_feat_exists(&mut state, has_feats);

    // setting funafl parameters
    set_alpha_init(&mut state, fun_args.factor_params.alpha);

    set_feat_mode(&mut state, fun_args.feat_mode);
    eprintln!("[factor-params] feat_mode={}", fun_args.feat_mode);

    set_explore_time(&mut state, fun_args.explore_time_secs);

    set_tpe_period(&mut state, fun_args.tpe_period_secs);
    eprintln!("[factor-params] explore_time={} hours, tpe_period={} minutes", 
        fun_args.explore_time_secs / 60 / 60, fun_args.tpe_period_secs / 60);

    set_factor_params(&mut state, fun_args.factor_params.clone());

    eprintln!(
        "[factor-params] alpha={:.3}, beta={:.3}, gmin={:.3}, gmax={:.3}, use_tanh={}",
        fun_args.factor_params.alpha, fun_args.factor_params.beta, fun_args.factor_params.gmin, fun_args.factor_params.gmax, fun_args.factor_params.use_tanh
    );
    eprintln!(
        "[params] features_enabled={}, features_map={}",
        get_features_enabled(&state),
        chosen_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".into())
    );
    eprintln!(
        "[params] timeout_ms={}, corpus_dir={}, crashes_dir={}, seeds_dir={}, tokens={}",
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
    eprintln!("[params] sancov_sites={}", sancov_sites);

    println!("Let's fuzz :)");

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::fast()),
        ),
    );

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        // reset the inline-counters map for each testcase
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        unsafe { core::ptr::write_bytes(cntrs_ptr, 0, sancov_sites); }

        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    };

    let mut tracing_harness = harness;

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        // tuple_list!(edges_observer, time_observer),
        tuple_list!(edges_observer, sancov_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    // Setup a tracing stage in which we log comparisons
    let tracing = TracingStage::new(
        InProcessExecutor::with_timeout(
            &mut tracing_harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout * 10,
        )?,
        // Give it more time!
    );

    // The order of the stages matter!
    // let mut stages = tuple_list!(calibration, tracing, i2s, power);
    let feat_stage = FeaturesAccountingStage {
        // map_name: "sancov",
        handle: sancov_handle,
        _p: core::marker::PhantomData,
    };

    // build TPE stage（period from CLI -> get_tpe_period())
    let tpe_stage = {
        let mut p = TpeParams::default();
        p.period = Duration::from_secs(get_tpe_period(&state));
        TpeStage::new(p)
    };
    // record baseline corpus, for ΔCorpus reward
    {
        let cur_corpus = state.corpus().count();
        tpe_stage.opt.set_last_corpus(cur_corpus);
    }

    let mut stages = tuple_list!(calibration, tracing, feat_stage, tpe_stage, i2s, power);

    // Read tokens
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

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Remove target output (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        if std::env::var("LIBAFL_FUZZBENCH_DEBUG").is_err() {
            dup2(null_fd, io::stderr().as_raw_fd())?;
        }
    }
    // reopen file to make sure we're at the end
    log.replace(OpenOptions::new().append(true).create(true).open(logfile)?);

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    // Never reached
    Ok(())
}
