#!/usr/bin/env python3
"""Gas comparison benchmark for MLIR-optimized Solidity compiler.

Compiles contracts with different compiler configurations, deploys to a local
Anvil node, executes test transactions, and compares gas usage.

Requirements:
- anvil (from foundry)
- cast (from foundry)
- solc with MLIR support
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "gas_results"

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
USE_COLOR = sys.stdout.isatty()


def _color(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{RESET}"


@dataclass
class CompilerConfig:
    """Compiler configuration for gas benchmarking."""
    config_id: str
    description: str
    solc_path: str
    flags: Sequence[str]

    def compile_cmd(self, source: Path, output_dir: Path) -> List[str]:
        cmd = [self.solc_path]
        cmd.extend(self.flags)
        cmd.extend(["--bin", "--abi", "-o", str(output_dir), "--overwrite"])
        cmd.append(str(source))
        return cmd


@dataclass
class TestCase:
    """A test case for gas benchmarking."""
    test_id: str
    description: str
    source_code: str
    contract_name: str
    # List of (function_signature, args) to call after deployment
    test_calls: Sequence[Tuple[str, Sequence[str]]]
    # Constructor args (if any)
    constructor_args: Sequence[str] = field(default_factory=list)


# Pre-defined test cases
TEST_CASES: Sequence[TestCase] = (
    TestCase(
        test_id="factorial",
        description="Factorial with storage caching opportunity",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FactorialStorage {
    uint256 public result;

    function computeFactorial(uint256 n) external {
        result = 1;
        for (uint256 i = 2; i <= n; ++i) {
            result *= i;
        }
    }

    function getResult() external view returns (uint256) {
        return result;
    }
}
''',
        contract_name="FactorialStorage",
        test_calls=[
            ("computeFactorial(uint256)", ["5"]),
            ("computeFactorial(uint256)", ["10"]),
            ("computeFactorial(uint256)", ["20"]),
        ],
    ),
    TestCase(
        test_id="counter",
        description="Simple counter with increment loop",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Counter {
    uint256 public count;

    function increment(uint256 times) external {
        for (uint256 i = 0; i < times; ++i) {
            count += 1;
        }
    }

    function reset() external {
        count = 0;
    }
}
''',
        contract_name="Counter",
        test_calls=[
            ("increment(uint256)", ["10"]),
            ("reset()", []),
            ("increment(uint256)", ["50"]),
        ],
    ),
    TestCase(
        test_id="sum-array",
        description="Sum computation with storage writes",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SumStorage {
    uint256 public total;

    function sumRange(uint256 start, uint256 end) external {
        total = 0;
        for (uint256 i = start; i <= end; ++i) {
            total += i;
        }
    }
}
''',
        contract_name="SumStorage",
        test_calls=[
            ("sumRange(uint256,uint256)", ["1", "10"]),
            ("sumRange(uint256,uint256)", ["1", "50"]),
            ("sumRange(uint256,uint256)", ["1", "100"]),
        ],
    ),
    TestCase(
        test_id="arithmetic",
        description="Mixed arithmetic operations",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Arithmetic {
    uint256 public value;

    function compute(uint256 a, uint256 b, uint256 iterations) external {
        value = a;
        for (uint256 i = 0; i < iterations; ++i) {
            value = (value * b + a) / 2;
            value = value % 1000000 + 1;
        }
    }
}
''',
        contract_name="Arithmetic",
        test_calls=[
            ("compute(uint256,uint256,uint256)", ["100", "3", "10"]),
            ("compute(uint256,uint256,uint256)", ["100", "3", "50"]),
        ],
    ),
)


def run(cmd: Sequence[str], cwd: Optional[Path] = None,
        timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a command and capture output."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, check=False, capture_output=True,
            text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")


def check_anvil() -> bool:
    """Check if anvil is available."""
    result = run(["which", "anvil"])
    return result.returncode == 0


def check_cast() -> bool:
    """Check if cast is available."""
    result = run(["which", "cast"])
    return result.returncode == 0


def start_anvil(port: int = 8545) -> subprocess.Popen:
    """Start an anvil instance."""
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--steps-tracing"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for anvil to start
    time.sleep(2)
    return proc


def stop_anvil(proc: subprocess.Popen) -> None:
    """Stop anvil instance."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def compile_contract(
    config: CompilerConfig,
    source_path: Path,
    output_dir: Path,
) -> Tuple[Optional[str], Optional[str], str]:
    """Compile contract and return (bytecode, abi, error)."""
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = config.compile_cmd(source_path, output_dir)
    result = run(cmd, timeout=120)

    if result.returncode != 0:
        return None, None, result.stderr

    # Find output files
    bin_files = list(output_dir.glob("*.bin"))
    abi_files = list(output_dir.glob("*.abi"))

    if not bin_files:
        return None, None, "No .bin file produced"

    bytecode = bin_files[0].read_text().strip()
    abi = abi_files[0].read_text() if abi_files else "[]"

    return bytecode, abi, ""


def deploy_contract(
    bytecode: str,
    rpc_url: str,
    private_key: str,
) -> Optional[str]:
    """Deploy contract and return address."""
    cmd = [
        "cast", "send", "--create", bytecode,
        "--rpc-url", rpc_url,
        "--private-key", private_key,
        "--json",
    ]
    result = run(cmd, timeout=60)

    if result.returncode != 0:
        print(f"Deploy failed: {result.stderr}")
        return None

    try:
        data = json.loads(result.stdout)
        return data.get("contractAddress")
    except json.JSONDecodeError:
        return None


def call_contract(
    address: str,
    signature: str,
    args: Sequence[str],
    rpc_url: str,
    private_key: str,
) -> Optional[int]:
    """Call contract function and return gas used."""
    cmd = [
        "cast", "send", address, signature,
        *args,
        "--rpc-url", rpc_url,
        "--private-key", private_key,
        "--json",
    ]
    result = run(cmd, timeout=60)

    if result.returncode != 0:
        print(f"Call failed: {result.stderr}")
        return None

    try:
        data = json.loads(result.stdout)
        return int(data.get("gasUsed", 0))
    except (json.JSONDecodeError, ValueError):
        return None


def run_benchmark(
    test_case: TestCase,
    configs: Sequence[CompilerConfig],
    rpc_url: str,
    private_key: str,
    work_dir: Path,
) -> Dict[str, object]:
    """Run benchmark for a test case across all configs."""
    results = {
        "test_id": test_case.test_id,
        "description": test_case.description,
        "configs": {},
    }

    # Write source file
    source_path = work_dir / f"{test_case.test_id}.sol"
    source_path.write_text(test_case.source_code)

    for config in configs:
        config_result = {
            "compile_status": "pending",
            "deploy_status": "pending",
            "gas_results": [],
            "total_gas": 0,
        }
        results["configs"][config.config_id] = config_result

        # Compile
        output_dir = work_dir / config.config_id
        bytecode, abi, error = compile_contract(config, source_path, output_dir)

        if not bytecode:
            config_result["compile_status"] = "failed"
            config_result["error"] = error[:500]
            continue

        config_result["compile_status"] = "ok"
        config_result["bytecode_size"] = len(bytecode) // 2  # hex to bytes

        # Deploy
        address = deploy_contract(bytecode, rpc_url, private_key)
        if not address:
            config_result["deploy_status"] = "failed"
            continue

        config_result["deploy_status"] = "ok"
        config_result["address"] = address

        # Run test calls
        total_gas = 0
        for sig, args in test_case.test_calls:
            gas = call_contract(address, sig, args, rpc_url, private_key)
            if gas is not None:
                config_result["gas_results"].append({
                    "call": f"{sig}({', '.join(args)})",
                    "gas": gas,
                })
                total_gas += gas
            else:
                config_result["gas_results"].append({
                    "call": f"{sig}({', '.join(args)})",
                    "gas": None,
                    "error": "call failed",
                })

        config_result["total_gas"] = total_gas

    return results


def print_results(all_results: List[Dict[str, object]], configs: Sequence[CompilerConfig]) -> None:
    """Print benchmark results as a table."""
    print("\n" + _color("=" * 80, CYAN))
    print(_color("Gas Comparison Results", BOLD))
    print(_color("=" * 80, CYAN))

    # Header
    header = f"{'Test Case':<25}"
    for config in configs:
        header += f" | {config.config_id:<15}"
    header += " | Improvement"
    print(header)
    print("-" * len(header))

    for result in all_results:
        row = f"{result['test_id']:<25}"

        gas_values = []
        for config in configs:
            cfg_result = result["configs"].get(config.config_id, {})
            gas = cfg_result.get("total_gas", 0)
            gas_values.append(gas)

            if cfg_result.get("compile_status") != "ok":
                cell = _color("COMPILE_ERR", RED)
            elif cfg_result.get("deploy_status") != "ok":
                cell = _color("DEPLOY_ERR", RED)
            elif gas > 0:
                cell = f"{gas:>15,}"
            else:
                cell = _color("N/A", YELLOW)

            row += f" | {cell:<15}"

        # Calculate improvement (baseline vs mlir-optimize)
        if len(gas_values) >= 2 and gas_values[0] > 0 and gas_values[1] > 0:
            improvement = ((gas_values[0] - gas_values[1]) / gas_values[0]) * 100
            if improvement > 0:
                imp_str = _color(f"+{improvement:.2f}%", GREEN)
            elif improvement < 0:
                imp_str = _color(f"{improvement:.2f}%", RED)
            else:
                imp_str = "0.00%"
            row += f" | {imp_str}"
        else:
            row += " | N/A"

        print(row)

    print("-" * len(header))

    # Summary
    print("\n" + _color("Summary:", BOLD))
    for config in configs:
        total = sum(
            r["configs"].get(config.config_id, {}).get("total_gas", 0)
            for r in all_results
        )
        print(f"  {config.config_id}: {total:,} total gas")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gas comparison benchmark for MLIR-optimized Solidity"
    )
    parser.add_argument(
        "--solc",
        required=True,
        help="Path to MLIR-enabled solc binary",
    )
    parser.add_argument(
        "--solc-baseline",
        help="Path to baseline solc (defaults to system solc)",
    )
    parser.add_argument(
        "--rpc-url",
        default="http://127.0.0.1:8545",
        help="Anvil RPC URL (default: http://127.0.0.1:8545)",
    )
    parser.add_argument(
        "--private-key",
        default="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        help="Private key for transactions (default: anvil account 0)",
    )
    parser.add_argument(
        "--start-anvil",
        action="store_true",
        help="Start anvil automatically",
    )
    parser.add_argument(
        "--tests",
        nargs="*",
        help="Subset of test IDs to run",
    )
    parser.add_argument(
        "--output",
        help="Output JSON file for results",
    )
    args = parser.parse_args(argv)

    # Check dependencies
    if not check_cast():
        print(_color("Error: 'cast' not found. Install foundry.", RED))
        return 1

    anvil_proc = None
    if args.start_anvil:
        if not check_anvil():
            print(_color("Error: 'anvil' not found. Install foundry.", RED))
            return 1
        print("Starting anvil...")
        anvil_proc = start_anvil()

    try:
        # Set up compiler configs
        baseline_solc = args.solc_baseline or "solc"
        configs = [
            CompilerConfig(
                config_id="via-ir-opt",
                description="Standard via-ir with optimizer",
                solc_path=baseline_solc,
                flags=["--via-ir", "--optimize"],
            ),
            CompilerConfig(
                config_id="mlir-opt",
                description="MLIR-optimized",
                solc_path=args.solc,
                flags=["--mlir-optimize"],
            ),
        ]

        # Select test cases
        if args.tests:
            test_map = {t.test_id: t for t in TEST_CASES}
            missing = [tid for tid in args.tests if tid not in test_map]
            if missing:
                print(_color(f"Unknown test IDs: {', '.join(missing)}", RED))
                return 1
            test_cases = [test_map[tid] for tid in args.tests]
        else:
            test_cases = list(TEST_CASES)

        print(f"Running {len(test_cases)} test cases with {len(configs)} configs")

        # Create work directory
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)

            all_results = []
            for test_case in test_cases:
                print(f"\nRunning: {test_case.test_id} - {test_case.description}")
                result = run_benchmark(
                    test_case, configs,
                    args.rpc_url, args.private_key,
                    work_path,
                )
                all_results.append(result)

            # Print results
            print_results(all_results, configs)

            # Save results
            if args.output:
                output_path = Path(args.output)
            else:
                RESULT_ROOT.mkdir(parents=True, exist_ok=True)
                output_path = RESULT_ROOT / "gas_latest.json"

            output_path.write_text(json.dumps(all_results, indent=2))
            print(f"\nResults saved to {output_path}")

    finally:
        if anvil_proc:
            print("Stopping anvil...")
            stop_anvil(anvil_proc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
