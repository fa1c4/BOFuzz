use std::{fmt, time::Duration};

use libafl::monitors::{ClientStats, Monitor, UserStatsValue};
use libafl_bolts::{current_time, format_duration_hms, ClientId};

#[derive(Clone)]
pub struct CustomMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
    start_time: Duration,
    print_user_monitor: bool,
    client_stats: Vec<ClientStats>,
}

impl<F> fmt::Debug for CustomMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats_len", &self.client_stats.len())
            .finish()
    }
}

impl<F> CustomMonitor<F>
where
    F: FnMut(&str),
{
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            print_user_monitor: false,
            client_stats: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            print_user_monitor: false,
            client_stats: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn with_user_monitor(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            print_user_monitor: true,
            client_stats: vec![],
        }
    }
}

impl<F> Monitor for CustomMonitor<F>
where
    F: FnMut(&str),
{
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    fn start_time(&self) -> Duration {
        self.start_time
    }

    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let line = format!(
            "[{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id.0,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats_count(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty()
        );
        (self.print_fn)(&line);

        let print_user_monitor = self.print_user_monitor;

        let mut to_print: Vec<String> = Vec::new();

        self.client_stats_insert(sender_id);
        {
            let client = self.client_stats_mut_for(sender_id);

            if print_user_monitor {
                for (key, val) in client.user_monitor.iter() {
                    if matches!(key.as_ref(), "features-info" | "tpe-info" | "tpe-trials") {
                        continue;
                    }
                    to_print.push(format!("[{}] {}", key, val));
                }
            }

            if let Some(u) = client.user_monitor.remove("features-info") {
                if let UserStatsValue::String(s) = u.value() {
                    if let Some(parsed) = parse_features_info(&s) {
                        let mut extra = String::new();
                        use std::fmt::Write as _;
                        write!(
                            extra,
                            "[BOFuzz features-info] enabled={} active={} mode={} exists={} α={:.2} β={:.2} g=[{:.2},{:.2}] tanh={} active_dim={} v_cands={} feat0={:.3} path_w={:.3} factor={:.3} v={}",
                            parsed.enabled, parsed.active, parsed.feat_mode, parsed.feat_exists,
                            parsed.alpha, parsed.beta, parsed.gmin, parsed.gmax, parsed.use_tanh,
                            parsed.active_dim, parsed.v_candidates_len, parsed.feat0, parsed.path_w, parsed.factor,
                            parsed.current_v
                        ).unwrap();
                        to_print.push(extra);
                    } else {
                        to_print.push(format!("[BOFuzz features-info] {}", s));
                    }
                }
            }

            if let Some(u) = client.user_monitor.remove("tpe-info") {
                if let UserStatsValue::String(s) = u.value() {
                    if let Some(parsed) = parse_tpe_info(&s) {
                        let mut extra = String::new();
                        use std::fmt::Write as _;
                        write!(
                            extra,
                            "[BOFuzz tpe-info] ΔEdges={:.1} Coverage={} trials={} corpus={} α={:.2} ‖v‖={:.2} active_dim={} bw={:.2} γ={:.2} samples={} period={} v={}",
                            parsed.reward, parsed.cov, parsed.trials, parsed.corpus,
                            parsed.alpha, parsed.v_norm, parsed.active_dim, parsed.bw, parsed.gamma,
                            parsed.samples, parsed.period, parsed.vec
                        ).unwrap();
                        to_print.push(extra);
                    } else {
                        to_print.push(format!("[BOFuzz tpe-info] {}", s));
                    }
                }
            }

            if let Some(u) = client.user_monitor.remove("tpe-trials") {
                if let UserStatsValue::String(s) = u.value() {
                    for l in s.lines() {
                        to_print.push(l.to_string());
                    }
                }
            }
        }

        for l in to_print {
            (self.print_fn)(&l);
        }
    }
}

#[derive(Default)]
struct FeaturesInfo {
    enabled: bool,
    active: bool,
    feat_exists: bool,
    feat_mode: u64,
    alpha: f64,
    beta: f64,
    gmin: f64,
    gmax: f64,
    use_tanh: bool,
    active_dim: u64,
    v_candidates_len: u64,
    current_v: String,
    feat0: f64,
    path_w: f64,
    factor: f64,
}

#[derive(Default)]
struct TpeInfo {
    reward: f64,
    cov: f64,
    trials: u64,
    corpus: u64,
    alpha: f64,
    v_norm: f64,
    active_dim: u64,
    vec: String,
    bw: f64,
    gamma: f64,
    samples: u64,
    period: String,
}

fn parse_features_info(s: &str) -> Option<FeaturesInfo> {
    let kv_part = strip_prefix_bracket(s)?;
    let mut out = FeaturesInfo::default();

    for seg in kv_part.split(',') {
        let seg = seg.trim();
        let (k, v) = split_kv(seg)?;
        match k {
            "enabled" => out.enabled = parse_bool(v),
            "active" => out.active = parse_bool(v),
            "feat_exists" => out.feat_exists = parse_bool(v),
            "feat_mode" => out.feat_mode = v.parse().ok().unwrap_or(0),
            "alpha" => out.alpha = parse_num(v),
            "beta" => out.beta = parse_num(v),
            "gmin" => out.gmin = parse_num(v),
            "gmax" => out.gmax = parse_num(v),
            "use_tanh" => out.use_tanh = parse_bool(v),
            "active_dim" => out.active_dim = v.parse().ok().unwrap_or(0),
            "v_candidates_len" => out.v_candidates_len = v.parse().ok().unwrap_or(0),
            "current_v" => out.current_v = v.to_string(),
            "feat0" => out.feat0 = parse_num(v),
            "path_w" => out.path_w = parse_num(v),
            "factor" => out.factor = parse_num(v),
            _ => {}
        }
    }
    Some(out)
}

fn parse_tpe_info(s: &str) -> Option<TpeInfo> {
    let kv_part = strip_prefix_bracket(s)?;
    let mut out = TpeInfo::default();

    for seg in kv_part.split(',') {
        let seg = seg.trim();
        let (k, v) = split_kv(seg)?;
        match k {
            "reward" => out.reward = parse_trailing_num(v),
            "Coverage" => out.cov = parse_trailing_num(v),
            "trials" => out.trials = v.parse().ok().unwrap_or(0),
            "corpus" => out.corpus = v.parse().ok().unwrap_or(0),
            "alpha" => out.alpha = parse_num(v),
            "v_norm" => out.v_norm = parse_num(v),
            "active_dim" => out.active_dim = v.parse().ok().unwrap_or(0),
            "v" => out.vec = v.to_string(),
            "bw" => out.bw = parse_num(v),
            "gamma" => out.gamma = parse_num(v),
            "samples" => out.samples = v.parse().ok().unwrap_or(0),
            "period" => out.period = v.to_string(),
            _ => {}
        }
    }
    Some(out)
}

fn strip_prefix_bracket(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.first().copied()? != b'[' {
        return Some(s);
    }
    let idx = s.find(']')?;
    let rest = s.get((idx + 1)..)?.trim_start();
    Some(rest)
}

fn split_kv(seg: &str) -> Option<(&str, &str)> {
    let mut it = seg.splitn(2, '=');
    Some((it.next()?.trim(), it.next()?.trim()))
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s,
        "1" | "true" | "True" | "TRUE" | "yes" | "Yes" | "on" | "On"
    )
}

fn parse_num(s: &str) -> f64 {
    s.trim_end_matches('%').parse::<f64>().unwrap_or(f64::NAN)
}

fn parse_trailing_num(s: &str) -> f64 {
    if let Some(idx) = s.rfind('=') {
        return parse_num(&s[idx + 1..]);
    }
    parse_num(s)
}
