/*
feature_sched/features_map.rs: load and parse the features_map.json data
*/
use serde::Deserialize;
use std::{fs::File, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(untagged)]
enum FeatsJson {
    Raw(Vec<f64>),
    Obj { features: Vec<f64> },
}

pub fn load_and_align_features_map(path: &Path, sites: usize) -> std::io::Result<Vec<f64>> {
    let mut f = File::open(path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let v: Vec<f64> = match serde_json::from_str::<FeatsJson>(&s).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json parse err: {e}"))
    })? {
        FeatsJson::Raw(v) => v,
        FeatsJson::Obj { features } => features,
    };
    Ok(align(v, sites))
}

fn align(mut v: Vec<f64>, sites: usize) -> Vec<f64> {
    if v.len() < sites { v.resize(sites, 0.0); }
    if v.len() > sites { v.truncate(sites); }
    v
}
