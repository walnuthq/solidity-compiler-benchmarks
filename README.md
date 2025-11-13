# Solidity Compiler Benchmark

This repository collects a handful of well-known Solidity contracts and scripts to evaulate compilers in many aspects. For now, it evaluates quality of ETHDebug generated, but it will contain benchmarks for gas, codesize, etc.

Currently, it runs the [`ethdebug-stats`](https://github.com/walnuthq/ethdebug-stats) analyzer against those popular contracts and it is designed to answer questions such as “how good are the source mappings for Uniswap, Aave, or Offchain Labs contracts when compiled with a given compiler build?”

An example:

```bash
./bench.py --compilers solc-0.8.30 solc-0.8.30-legacy solc-0.8.28 solx solar

Analyzed 5 contracts.

Line Coverage Averages:
  * solc-0.8.30-via-ir: 80.00%
  * solc-0.8.30-legacy: 0.00%
  * solc-0.8.28-via-ir: 0.00%
  * solx: 0.00%
  * solar: 0.00%

Variable Location Coverage Averages:
  * solc-0.8.30-via-ir: 0.00%
  * solc-0.8.30-legacy: 0.00%
  * solc-0.8.28-via-ir: 0.00%
  * solx: 0.00%
  * solar: 0.00%
```

> Note: this repo pulls upstream contracts via git submodules. Clone with --recurse-submodules (or run git submodule update --init --recursive) before running the benchmark.


## Running the benchmark

1. Ensure you have `solc-select` and the desired compiler versions installed:
   ```bash
   solc-select install 0.8.30 0.8.29
   solc-select use 0.8.30
   ```
   The script automatically switches between the requested versions. Contracts with strict pragmas (e.g., Uniswap V2) will be skipped if the required compiler is not available.

2. Activate the Python environment where `ethdebug-stats` is installed.

3. Run the benchmark:
   ```bash
   cd ethdebug-benchmark
   ./bench.py                        # use the default compiler set (summary table)
   ./bench.py --verbose              # include per-contract logs
   ./bench.py --compilers solc-0.8.30 solc-0.8.30-legacy # compare via-ir vs legacy pipeline
   ```

By default the CLI prints aggregated metrics (average line/variable coverage per compiler). Add `--verbose` if you prefer the detailed per-contract log instead.

Each run writes a JSON + CSV summary into `results/` and the raw compiler artifacts into `artifacts/`. The `latest.(json|csv)` files always reference the most recent run so they can be fed into plotting tools directly. Every result row contains:

- `coverage`: the `source_coverage_percent` reported by `ethdebug-stats`
- `variable_metadata_present`: `1` if the ethdebug blob included any variable or
  parameter metadata, otherwise `0`
- `variable_coverage_percent`: share of instructions that carried variable
  metadata (always `0` today, but keeps plots ready for future compiler
  support)
- `contract_name`: fully qualified contract that was passed to `ethdebug-stats`
- `repo` / `source`: which repository subtree and Solidity file were compiled
- `status`: `ok`, `pragma_incompatible`, `compiler_unavailable`, `failed`, etc.
- `notes`: location of the analyzed ethdebug blob or the failure reason

Compiler rows currently mean the following:

- `solc-0.8.30` / `solc-0.8.29`: official solc builds invoked with `--via-ir`
  and `--ethdebug`. They emit ethdebug data and therefore show meaningful
  coverage.
- `solc-0.8.30-legacy` / `solc-0.8.29-legacy`: same binaries but without
  `--via-ir`. Solc refuses to produce ethdebug in this mode, so the CSV/JSON
  will have `status=failed` and `coverage=0`, making the dependency on the IR
  pipeline explicit.
- `solx`, `solar`: placeholder compilers that currently do not implement
  ethdebug output. They stay in the dataset as a reminder and immediately show
  zero coverage.
- Any other `solc-X.Y.Z` you pass on the command line is accepted dynamically:
  if `X.Y.Z < 0.8.29` the script knows ethdebug is unavailable and records
  zero line/variable coverage with `status=no_ethdebug_support`.
