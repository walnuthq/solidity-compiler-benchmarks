#!/usr/bin/env python3
"""Compare solc and Solar codegen on curated Solidity micro-benchmarks."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from gas_bench import TEST_CASES, TestCase

ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "solar_results"
DEFAULT_RPC_URL = "http://127.0.0.1:8545"
DEFAULT_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
USE_COLOR = sys.stdout.isatty()
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _color(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{RESET}"


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def pad_cell(text: str, width: int) -> str:
    return text + " " * max(0, width - visible_len(text))


def run(
    cmd: Sequence[str],
    input_text: Optional[str] = None,
    timeout: int = 120,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            input=input_text,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")


def find_binary(explicit: Optional[str], candidates: Sequence[str]) -> Optional[Path]:
    if explicit:
        path = Path(explicit)
        if path.exists():
            return path.resolve()
        found = shutil.which(explicit)
        if found:
            return Path(found).resolve()
        return None

    for candidate in candidates:
        path = Path(candidate)
        if not path.is_absolute():
            path = ROOT / candidate
        if path.exists():
            return path.resolve()
        found = shutil.which(candidate)
        if found:
            return Path(found).resolve()
    return None


def binary_version(path: Path) -> Tuple[str, str]:
    result = run([str(path), "--version"], timeout=30)
    if result.returncode != 0:
        error = (result.stderr or result.stdout or "version command failed").strip()
        return "unavailable", error[:500]
    text = (result.stdout + "\n" + result.stderr).strip()
    match = re.search(r"(\d+\.\d+\.\d+(?:[-+][^\s]+)?)", text)
    version = match.group(1) if match else text.splitlines()[0] if text else "unknown"
    return version, ""


@dataclass(frozen=True)
class CompilerSpec:
    compiler_id: str
    label: str
    path: Path
    kind: str


@dataclass(frozen=True)
class SourceCase:
    test_id: str
    description: str
    project: str
    repo: str
    source: str
    contract_name: str
    import_paths: Sequence[str] = field(default_factory=tuple)
    remappings: Sequence[str] = field(default_factory=tuple)
    test_calls: Sequence[Tuple[str, Sequence[str]]] = field(default_factory=tuple)
    constructor_args: Sequence[str] = field(default_factory=tuple)
    constructor_sig: Optional[str] = None

    @property
    def source_path(self) -> Path:
        return ROOT / self.repo / self.source

    @property
    def repo_path(self) -> Path:
        return ROOT / self.repo


REPO_TEST_CASES: Sequence[SourceCase] = (
    SourceCase(
        test_id="uniswap-v2-pair",
        description="Uniswap V2 Pair",
        project="v2-core",
        repo="v2-core",
        source="contracts/UniswapV2Pair.sol",
        contract_name="UniswapV2Pair",
    ),
    SourceCase(
        test_id="openzeppelin-erc20-mock",
        description="OpenZeppelin ERC20Mock",
        project="openzeppelin-contracts",
        repo="openzeppelin-contracts",
        source="contracts/mocks/token/ERC20Mock.sol",
        contract_name="ERC20Mock",
    ),
    SourceCase(
        test_id="openzeppelin-vesting-wallet",
        description="OpenZeppelin VestingWallet",
        project="openzeppelin-contracts",
        repo="openzeppelin-contracts",
        source="contracts/finance/VestingWallet.sol",
        contract_name="VestingWallet",
    ),
    SourceCase(
        test_id="nitro-one-step-proof",
        description="Nitro OneStepProofEntry",
        project="nitro-contracts",
        repo="nitro-contracts",
        source="src/osp/OneStepProofEntry.sol",
        contract_name="OneStepProofEntry",
    ),
    SourceCase(
        test_id="aave-l2-encoder",
        description="Aave V3 L2Encoder",
        project="aave-v3-core",
        repo="aave-v3-core",
        source="contracts/misc/L2Encoder.sol",
        contract_name="L2Encoder",
    ),
    SourceCase(
        test_id="lilweb3-ens",
        description="LilENS",
        project="lil-web3",
        repo="lil-web3",
        source="src/LilENS.sol",
        contract_name="LilENS",
        test_calls=(("register(string)", ("testname",)), ("lookup(string)", ("testname",))),
    ),
    SourceCase(
        test_id="lilweb3-flashloan",
        description="LilFlashloan",
        project="lil-web3",
        repo="lil-web3",
        source="src/LilFlashloan.sol",
        contract_name="LilFlashloan",
        remappings=("solmate/=lib/solmate/src/",),
    ),
    SourceCase(
        test_id="lilweb3-fractional",
        description="LilFractional",
        project="lil-web3",
        repo="lil-web3",
        source="src/LilFractional.sol",
        contract_name="LilFractional",
        remappings=("solmate/=lib/solmate/src/",),
    ),
    SourceCase(
        test_id="maple-erc20",
        description="Maple ERC20",
        project="maple-erc20",
        repo="maple-erc20",
        source="contracts/ERC20.sol",
        contract_name="ERC20",
    ),
)


def standard_json_input(test_case: TestCase) -> str:
    payload = {
        "language": "Solidity",
        "sources": {
            f"{test_case.test_id}.sol": {
                "content": test_case.source_code,
            }
        },
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "viaIR": True,
            "outputSelection": {
                "*": {
                    "*": [
                        "abi",
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object",
                    ]
                }
            },
        },
    }
    return json.dumps(payload)


def parse_standard_json_output(stdout: str, test_case: TestCase) -> Tuple[Optional[str], Optional[str], str]:
    try:
        output = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return None, None, f"invalid JSON output: {exc}"

    errors = output.get("errors") or []
    fatal = [
        err.get("formattedMessage") or err.get("message") or str(err)
        for err in errors
        if err.get("severity") == "error"
    ]
    if fatal:
        return None, None, fatal[0][:1000]

    contracts = output.get("contracts") or {}
    for source_contracts in contracts.values():
        if test_case.contract_name in source_contracts:
            contract = source_contracts[test_case.contract_name]
            evm = contract.get("evm") or {}
            bytecode = ((evm.get("bytecode") or {}).get("object") or "").strip()
            deployed = ((evm.get("deployedBytecode") or {}).get("object") or "").strip()
            if bytecode:
                return bytecode, deployed, ""

    available = [
        name
        for source_contracts in contracts.values()
        for name in source_contracts.keys()
    ]
    return None, None, f"contract {test_case.contract_name} not found; available: {', '.join(available)}"


def compile_standard_json(spec: CompilerSpec, test_case: TestCase) -> Dict[str, object]:
    result = {
        "compiler_id": spec.compiler_id,
        "label": spec.label,
        "status": "pending",
        "bytecode": "",
        "runtime_bytecode": "",
        "bytecode_size": 0,
        "runtime_size": 0,
        "error": "",
    }
    proc = run([str(spec.path), "--standard-json"], input_text=standard_json_input(test_case), timeout=120)
    result["command"] = f"{spec.path} --standard-json"
    if proc.returncode != 0:
        result["status"] = "failed"
        result["error"] = (proc.stderr or proc.stdout or "compiler failed")[:1000]
        return result

    bytecode, runtime, error = parse_standard_json_output(proc.stdout, test_case)
    if not bytecode:
        result["status"] = "failed"
        result["error"] = error
        return result

    result["status"] = "ok"
    result["bytecode"] = bytecode
    result["runtime_bytecode"] = runtime or ""
    result["bytecode_size"] = len(bytecode) // 2
    result["runtime_size"] = len(runtime or "") // 2
    return result


def parse_solar_cli_output(stdout: str, case: SourceCase) -> Tuple[Optional[str], Optional[str], str]:
    decoder = json.JSONDecoder()
    objects = []
    idx = 0
    while idx < len(stdout):
        while idx < len(stdout) and stdout[idx].isspace():
            idx += 1
        if idx >= len(stdout):
            break
        try:
            obj, idx = decoder.raw_decode(stdout, idx)
        except json.JSONDecodeError as exc:
            return None, None, f"invalid JSON output: {exc}"
        if isinstance(obj, dict):
            objects.append(obj)

    output = next((obj for obj in reversed(objects) if obj.get("contracts")), {})
    if not output:
        return None, None, "no contracts in JSON output"

    errors = output.get("errors") or []
    fatal = [
        err.get("formattedMessage") or err.get("message") or str(err)
        for err in errors
        if err.get("severity") == "error"
    ]
    if fatal:
        return None, None, fatal[0][:1000]

    contracts = output.get("contracts") or {}
    for key, contract in contracts.items():
        if key == case.contract_name or key.endswith(f":{case.contract_name}"):
            bytecode = str(contract.get("bin") or "").strip()
            runtime = str(contract.get("bin-runtime") or contract.get("bin_runtime") or "").strip()
            if bytecode:
                return bytecode, runtime, ""

    available = ", ".join(str(key) for key in contracts.keys())
    return None, None, f"contract {case.contract_name} not found; available: {available}"


def compile_repo_case(spec: CompilerSpec, case: SourceCase) -> Dict[str, object]:
    result = {
        "compiler_id": spec.compiler_id,
        "label": spec.label,
        "status": "pending",
        "bytecode": "",
        "runtime_bytecode": "",
        "bytecode_size": 0,
        "runtime_size": 0,
        "error": "",
        "source": str(case.source_path.relative_to(ROOT)),
        "project": case.project,
    }

    if not case.source_path.exists():
        result["status"] = "failed"
        result["error"] = (
            f"source not found: {case.source_path.relative_to(ROOT)}; "
            "run `git submodule update --init --recursive`"
        )
        return result

    with tempfile.TemporaryDirectory(prefix="solar-bench-") as tmp:
        out_dir = Path(tmp) / spec.compiler_id
        out_dir.mkdir(parents=True, exist_ok=True)

        if spec.kind == "solc":
            cmd = [
                str(spec.path),
                "--via-ir",
                "--optimize",
                "--bin",
                "--bin-runtime",
                "--abi",
                "--base-path",
                str(case.repo_path),
                "--overwrite",
                "-o",
                str(out_dir),
            ]
            for import_path in case.import_paths:
                cmd.extend(["--include-path", import_path])
            cmd.extend(case.remappings)
            cmd.append(case.source)
            proc = run(cmd, timeout=180, cwd=case.repo_path)
            result["command"] = " ".join(cmd)
            if proc.returncode != 0:
                result["status"] = "failed"
                result["error"] = (proc.stderr or proc.stdout or "compiler failed")[:1000]
                return result

            bytecode_path = out_dir / f"{case.contract_name}.bin"
            runtime_path = out_dir / f"{case.contract_name}.bin-runtime"
            if not bytecode_path.exists():
                result["status"] = "failed"
                result["error"] = f"{bytecode_path.name} was not produced"
                return result
            bytecode = bytecode_path.read_text().strip()
            runtime = runtime_path.read_text().strip() if runtime_path.exists() else ""
        else:
            cmd = [
                str(spec.path),
                "--emit",
                "abi,bin,bin-runtime",
                "--base-path",
                str(case.repo_path),
                "--color",
                "never",
            ]
            for import_path in case.import_paths:
                cmd.extend(["-I", import_path])
            cmd.extend(case.remappings)
            cmd.append(case.source)
            proc = run(cmd, timeout=180, cwd=case.repo_path)
            result["command"] = " ".join(cmd)
            if proc.returncode != 0:
                result["status"] = "failed"
                result["error"] = (proc.stderr or proc.stdout or "compiler failed")[:1000]
                return result
            bytecode, runtime, error = parse_solar_cli_output(proc.stdout, case)
            if not bytecode:
                result["status"] = "failed"
                result["error"] = error
                return result

    result["status"] = "ok"
    result["bytecode"] = bytecode
    result["runtime_bytecode"] = runtime or ""
    result["bytecode_size"] = len(bytecode) // 2
    result["runtime_size"] = len(runtime or "") // 2
    return result


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def start_anvil(port: int = 8545) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--steps-tracing"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)
    return proc


def stop_anvil(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def abi_encode_constructor(constructor_args: Sequence[str], constructor_sig: Optional[str]) -> Optional[str]:
    if not constructor_args:
        return ""
    if not constructor_sig:
        return None
    proc = run(["cast", "abi-encode", constructor_sig, *constructor_args], timeout=30)
    if proc.returncode != 0:
        return None
    encoded = proc.stdout.strip()
    return encoded[2:] if encoded.startswith("0x") else encoded


def deploy_contract(
    bytecode: str,
    test_case: TestCase,
    rpc_url: str,
    private_key: str,
) -> Tuple[Optional[str], str]:
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode

    constructor_sig = getattr(test_case, "constructor_sig", None)
    encoded = abi_encode_constructor(test_case.constructor_args, constructor_sig)
    if encoded is None:
        return None, "constructor args require constructor_sig"
    bytecode += encoded

    proc = run(
        [
            "cast",
            "send",
            "--rpc-url",
            rpc_url,
            "--private-key",
            private_key,
            "--json",
            "--create",
            bytecode,
        ],
        timeout=60,
    )
    if proc.returncode != 0:
        return None, proc.stderr[:1000]
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return None, f"invalid deploy JSON: {exc}"
    return data.get("contractAddress"), ""


def call_contract(
    address: str,
    signature: str,
    args: Sequence[str],
    rpc_url: str,
    private_key: str,
) -> Tuple[Optional[int], str]:
    proc = run(
        [
            "cast",
            "send",
            address,
            signature,
            *args,
            "--rpc-url",
            rpc_url,
            "--private-key",
            private_key,
            "--json",
        ],
        timeout=60,
    )
    if proc.returncode != 0:
        return None, proc.stderr[:1000]
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return None, f"invalid call JSON: {exc}"
    gas = data.get("gasUsed")
    if isinstance(gas, str):
        return int(gas, 16) if gas.startswith("0x") else int(gas), ""
    return int(gas), ""


def run_test_case(
    test_case: TestCase | SourceCase,
    specs: Sequence[CompilerSpec],
    include_gas: bool,
    rpc_url: str,
    private_key: str,
) -> Dict[str, object]:
    entry: Dict[str, object] = {
        "test_id": test_case.test_id,
        "description": test_case.description,
        "contract_name": test_case.contract_name,
        "suite": "repo" if isinstance(test_case, SourceCase) else "micro",
        "compilers": {},
    }
    if isinstance(test_case, SourceCase):
        entry["project"] = test_case.project
        entry["source"] = str(test_case.source_path.relative_to(ROOT))

    for spec in specs:
        compiled = (
            compile_repo_case(spec, test_case)
            if isinstance(test_case, SourceCase)
            else compile_standard_json(spec, test_case)
        )
        compiler_entry = dict(compiled)
        compiler_entry.pop("bytecode", None)
        entry["compilers"][spec.compiler_id] = compiler_entry

        if compiled["status"] != "ok" or not include_gas:
            continue

        address, deploy_error = deploy_contract(
            str(compiled["bytecode"]),
            test_case,
            rpc_url,
            private_key,
        )
        if not address:
            compiler_entry["deploy_status"] = "failed"
            compiler_entry["deploy_error"] = deploy_error
            continue

        compiler_entry["deploy_status"] = "ok"
        compiler_entry["address"] = address
        gas_results = []
        total_gas = 0
        for signature, args in test_case.test_calls:
            gas, error = call_contract(address, signature, args, rpc_url, private_key)
            if gas is None:
                gas_results.append({"call": signature, "args": list(args), "gas": None, "error": error})
                continue
            gas_results.append({"call": signature, "args": list(args), "gas": gas})
            total_gas += gas
        compiler_entry["gas_results"] = gas_results
        compiler_entry["total_gas"] = total_gas

    return entry


def pct_delta(old: int, new: int) -> str:
    if old <= 0 or new <= 0:
        return "N/A"
    delta = ((old - new) / old) * 100.0
    color = GREEN if delta >= 0 else RED
    prefix = "+" if delta >= 0 else ""
    return _color(f"{prefix}{delta:.2f}%", color)


def print_size_table(results: Sequence[Dict[str, object]], specs: Sequence[CompilerSpec]) -> None:
    print("\n" + _color("Code Size Comparison", BOLD))
    test_width = max(22, *(visible_len(str(result["test_id"])) for result in results)) if results else 22
    header = f"{'Test':<{test_width}}"
    for spec in specs:
        header += f" | {spec.compiler_id:<13}"
    header += " | Solar vs solc"
    print(header)
    print("-" * len(header))

    for result in results:
        row = f"{str(result['test_id']):<{test_width}}"
        sizes = []
        for spec in specs:
            data = result["compilers"].get(spec.compiler_id, {})
            size = int(data.get("runtime_size") or data.get("bytecode_size") or 0)
            sizes.append(size)
            if data.get("status") != "ok":
                cell = _color("FAILED", RED)
            else:
                cell = f"{size:,}B"
            row += f" | {pad_cell(cell, 13)}"
        row += f" | {pct_delta(sizes[0], sizes[1]) if len(sizes) >= 2 else 'N/A'}"
        print(row)


def print_gas_table(results: Sequence[Dict[str, object]], specs: Sequence[CompilerSpec]) -> None:
    print("\n" + _color("Gas Comparison", BOLD))
    test_width = max(22, *(visible_len(str(result["test_id"])) for result in results)) if results else 22
    header = f"{'Test':<{test_width}}"
    for spec in specs:
        header += f" | {spec.compiler_id:<13}"
    header += " | Solar vs solc"
    print(header)
    print("-" * len(header))

    for result in results:
        row = f"{str(result['test_id']):<{test_width}}"
        totals = []
        for spec in specs:
            data = result["compilers"].get(spec.compiler_id, {})
            gas = int(data.get("total_gas") or 0)
            totals.append(gas)
            if data.get("status") != "ok":
                cell = _color("COMPILE_ERR", RED)
            elif data.get("deploy_status") == "failed":
                cell = _color("DEPLOY_ERR", RED)
            elif gas <= 0:
                cell = _color("N/A", YELLOW)
            else:
                cell = f"{gas:,}"
            row += f" | {pad_cell(cell, 13)}"
        row += f" | {pct_delta(totals[0], totals[1]) if len(totals) >= 2 else 'N/A'}"
        print(row)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark solc vs Solar codegen on inline and repository contracts"
    )
    parser.add_argument("--solc", default="solc", help="Path to solc binary (default: solc)")
    parser.add_argument(
        "--solar",
        help="Path to solar binary (default: solar, ../solar/target/release/solar, ../solar/target/debug/solar)",
    )
    parser.add_argument("--suite", choices=("micro", "repo", "all"), default="micro", help="Benchmark suite to run")
    parser.add_argument("--tests", nargs="*", help="Subset of test IDs to run")
    parser.add_argument("--projects", nargs="*", help="Subset of repository project names to run")
    parser.add_argument("--list-tests", action="store_true", help="List available tests and exit")
    parser.add_argument("--gas", action="store_true", help="Deploy and execute gas test calls with cast/anvil")
    parser.add_argument("--start-anvil", action="store_true", help="Start anvil automatically for --gas")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL, help=f"RPC URL (default: {DEFAULT_RPC_URL})")
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY, help="Private key for transactions")
    parser.add_argument("--output", help="Output JSON path")
    parser.add_argument("--verbose", action="store_true", help="Print compiler errors for failed rows")
    parser.add_argument(
        "--allow-failures",
        action="store_true",
        help="Exit successfully even if a compiler fails for one or more tests",
    )
    args = parser.parse_args(argv)

    all_tests = []
    if args.suite in ("micro", "all"):
        all_tests.extend(TEST_CASES)
    if args.suite in ("repo", "all"):
        all_tests.extend(REPO_TEST_CASES)

    if args.projects:
        project_set = set(args.projects)
        all_tests = [
            test for test in all_tests
            if isinstance(test, SourceCase) and test.project in project_set
        ]

    test_map = {test.test_id: test for test in all_tests}
    if args.list_tests:
        for test in all_tests:
            if isinstance(test, SourceCase):
                print(f"{test.test_id}	{test.project}	{test.source}	{test.contract_name}")
            else:
                print(f"{test.test_id}	micro	inline	{test.contract_name}")
        return 0

    solc = find_binary(args.solc, ["solc"])
    if not solc:
        print(_color(f"solc not found: {args.solc}", RED), file=sys.stderr)
        return 1

    solar = find_binary(
        args.solar,
        [
            "solar",
            "../solar/target/release/solar",
            "../solar/target/debug/solar",
        ],
    )
    if not solar:
        print(_color("solar binary not found; build Solar or pass --solar /path/to/solar", RED), file=sys.stderr)
        return 1

    if args.gas and not check_tool("cast"):
        print(_color("cast not found; install Foundry or omit --gas", RED), file=sys.stderr)
        return 1

    anvil_proc = None
    if args.gas and args.start_anvil:
        if not check_tool("anvil"):
            print(_color("anvil not found; install Foundry or omit --start-anvil", RED), file=sys.stderr)
            return 1
        print("Starting anvil...")
        anvil_proc = start_anvil()

    solc_version, solc_version_error = binary_version(solc)
    solar_version, solar_version_error = binary_version(solar)

    specs = [
        CompilerSpec("solc", f"solc {solc_version}", solc, "solc"),
        CompilerSpec("solar", f"solar {solar_version}", solar, "solar"),
    ]

    if args.tests:
        missing = [test_id for test_id in args.tests if test_id not in test_map]
        if missing:
            print(_color(f"unknown test IDs: {', '.join(missing)}", RED), file=sys.stderr)
            return 1
        tests = [test_map[test_id] for test_id in args.tests]
    else:
        tests = list(all_tests)

    if args.gas and any(isinstance(test, SourceCase) and not test.test_calls for test in tests):
        print(_color("repo contracts without gas calls will show N/A in the gas table", YELLOW), file=sys.stderr)

    print(f"Using {specs[0].label}")
    if solc_version_error:
        print(
            _color(
                "Warning: `solc --version` failed. If this is solc-select, run "
                "`solc-select install 0.8.30 && solc-select use 0.8.30` or pass --solc /path/to/solc.",
                YELLOW,
            ),
            file=sys.stderr,
        )
    print(f"Using {specs[1].label}")
    if solar_version_error:
        print(_color(f"Warning: `solar --version` failed: {solar_version_error}", YELLOW), file=sys.stderr)
    print(f"Running {len(tests)} tests")

    try:
        results = [
            run_test_case(test, specs, args.gas, args.rpc_url, args.private_key)
            for test in tests
        ]
    finally:
        if anvil_proc:
            print("Stopping anvil...")
            stop_anvil(anvil_proc)

    print_size_table(results, specs)
    if args.gas:
        print_gas_table(results, specs)

    if args.verbose:
        for result in results:
            for compiler_id, data in result["compilers"].items():
                if data.get("status") != "ok":
                    print(f"\n{result['test_id']} {compiler_id} error:\n{data.get('error', '')}")

    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    output = Path(args.output) if args.output else RESULT_ROOT / "solar_latest.json"
    output.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {output}")

    failed = [
        (result["test_id"], compiler_id)
        for result in results
        for compiler_id, data in result["compilers"].items()
        if data.get("status") != "ok"
    ]
    if failed and not args.allow_failures:
        print(
            _color(f"{len(failed)} compiler runs failed; use --allow-failures to keep exit code 0", RED),
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
