# Solidity Compiler Benchmark

This repository collects a handful of well-known Solidity contracts and scripts to evaluate compilers in many aspects:

- **ETHDebug coverage** (`bench.py`) - Evaluates quality of debug information
- **MLIR compilation testing** (`mlir_bench.py`) - Tests MLIR pipeline compatibility
- **Gas comparison** (`gas_bench.py`) - Compares gas usage between compiler configurations

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

---

## MLIR Pipeline Benchmarks

### MLIR Compilation Testing (`mlir_bench.py`)

Tests the MLIR compilation pipeline across contracts to identify supported/unsupported features, with optional code size and gas usage comparisons.

**Prerequisites:**
- MLIR-enabled solc build
- [solx](https://github.com/matter-labs/solx) (optional, for comparison)
- [Foundry](https://getfoundry.sh/) installed (`anvil`, `cast`) for gas benchmarks

#### Quick Start

```bash
# 1. Compilation tests only (default)
./mlir_bench.py --solc ../solidity/build/solc/solc --only-mlir-modes

# 2. Code size comparison (solc via-ir vs mlir vs solx)
./mlir_bench.py --solc ../solidity/build/solc/solc --only-mlir-modes \
    --solx /path/to/solx --codesize

# 3. Full benchmark: compilation + code size + gas comparison
./mlir_bench.py --solc ../solidity/build/solc/solc --only-mlir-modes \
    --solx /path/to/solx --codesize --gas --start-anvil
```

#### Benchmark Modes

| Flag | Description |
|------|-------------|
| (default) | Compilation tests only - verifies MLIR pipeline works |
| `--codesize` | Compare bytecode sizes: `solc --via-ir` vs `solc --mlir-optimize` vs `solx` |
| `--gas` | Compare runtime gas usage (requires anvil) |
| `--all` | Run all benchmarks (compilation + codesize + gas) |

#### Examples

```bash
# Code size comparison across 30 contracts
./mlir_bench.py --solc ../solidity/build/solc/solc --only-mlir-modes \
    --solx /path/to/solx --codesize

# Example output:
# Contract                    | solc --via-ir | solc --mlir | solx --via-ir | Improvement
# WETH - Wrapped Ether        |         4,032 |         203 |        FAILED | +95.0%
# LilFractional - NFT         |         5,712 |         432 |         7,501 | +92.4%
# LilGnosis - Multisig        |         3,077 |         304 |         3,906 | +90.1%
# Total                       |        32,945 |       5,771 |        22,321 | +82.5%
```

```bash
# Gas comparison with auto-started anvil
./mlir_bench.py --solc ../solidity/build/solc/solc --only-mlir-modes \
    --solx /path/to/solx --gas --start-anvil

# Example output:
# Test Case        | solc --via-ir | solc --mlir | solx --via-ir | Improvement
# storage-patterns |     1,726,964 |     154,152 |     1,696,316 | +91.07%
# weth-wrapper     |        70,840 |      43,963 |        70,552 | +37.94%
# sum-range        |       145,188 |     107,711 |       115,424 | +25.81%
# Total            |     2,465,960 |     766,944 |     2,382,098 | +68.9%
```

```bash
# Full benchmark with all comparisons
./mlir_bench.py --solc ../solidity/build/solc/solc --only-mlir-modes \
    --solx /path/to/solx --all --start-anvil
```

#### Additional Options

```bash
# Verbose output with error details
./mlir_bench.py --solc ../solidity/build/solc/solc --verbose

# Test specific contracts
./mlir_bench.py --solc ../solidity/build/solc/solc --contracts pitfalls-noaccess solmate-weth

# Test specific gas benchmarks
./mlir_bench.py --solc ../solidity/build/solc/solc --gas --start-anvil \
    --gas-tests factorial erc20-wrapper

# Use existing anvil instance
./mlir_bench.py --solc ../solidity/build/solc/solc --gas \
    --rpc-url http://127.0.0.1:8545

# Include MLIR test contracts from solidity repo
./mlir_bench.py --solc ../solidity/build/solc/solc --include-mlir-tests
```

#### Gas Test Cases

| Test | Description |
|------|-------------|
| `factorial` | Storage caching optimization (loop with storage writes) |
| `counter` | Simple increment loop |
| `sum-range` | Range summation with storage |
| `arithmetic` | Mixed arithmetic operations |
| `erc20-wrapper` | ERC20 token operations (mint, transfer, approve) |
| `erc721-wrapper` | ERC721 NFT operations (mint, transfer) |
| `weth-wrapper` | Wrapped Ether operations |
| `storage-patterns` | Common storage access patterns |
| `math-intensive` | Fibonacci, prime check, power, GCD |

#### Compilation Modes

- `baseline` - Standard `--bin` compilation
- `mlir-optimize` - MLIR-optimized compilation (`--mlir-optimize --bin`)
- `mlir-print` - Print MLIR dialect (`--mlir-optimize --print-mlir`)
- `mlir-analyze` - MLIR security analysis (`--mlir-optimize --mlir-analyze --bin`)
- `via-ir-optimize` - Standard via-ir with optimizer

#### Error Categories

The benchmark categorizes compilation failures to track MLIR implementation gaps:
- `mlir_type_mismatch` - Type errors in MLIR operations
- `mlir_parent_op` - CFG/region structure issues
- `mlir_verifier` - MLIR verification failures
- `import_error` - Missing dependencies
- `unimplemented` - Features not yet implemented

Results are saved to `mlir_results/` as JSON and CSV.

---

### Legacy Gas Comparison (`gas_bench.py`)

Standalone gas comparison script (simpler, fewer test cases).

```bash
# Start anvil and run benchmarks
./gas_bench.py --solc ../solidity/build/solc/solc --start-anvil

# Use existing anvil instance
./gas_bench.py --solc ../solidity/build/solc/solc --rpc-url http://127.0.0.1:8545

# Run specific test cases
./gas_bench.py --solc ../solidity/build/solc/solc --tests factorial counter
```

Results show gas comparison between `via-ir --optimize` and `--mlir-optimize`.
