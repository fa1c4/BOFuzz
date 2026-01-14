# FunAFL Prototype
FunAFL (v2.0+) is based on LibAFL 0.15.0 version. 

## Setup
Dependencies: LLVM-15+, Rust

## Test
```shell
cd fuzzers/inprocess/libfun

cargo clean && cargo build --profile release-libfun --features no_link_main                                                                         ✔ 
clang -c stub_rt.c -o stub_rt.o
ar r ./stub_rt.a stub_rt.o
```

build and run the example with funafl
```shell
cd ../../../example
./zlib_uncompress_demo.sh
```

# Normal Usage of FunAFL 
1.After building fuzzer, then compile the target program with instrumentor of funafl to get funafl-specific intrumented target binary
2.Run the static analysis script to extract features_map from target binary. Dependencies: IDA Pro v7.7 (tested)
then put the features_map file `{target_name}_features_map.json` into target binary directory (the default read path of features_map)
3.Running the fuzzer in the way like
```shell
./{your_target}_fuzzer --alpha 0.6 --feat-mode 2 --explore-time 3600 --tpe-period 600 -i "/path/to/corpus" -o "/path/to/findings"
```

## Evaluation
Coverage results dataset of funafl and baselines are stored at `eval/data`
```shell
cd eval/src
python fun_eval_coverage.py
```
the coverage plots will be saved at eval/results/fuzzer_coverage_evaluation.png
