#!/usr/bin/env python3
"""Run ethdebug coverage benchmarks across curated contracts and compiler variants."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
import re

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / "artifacts"
RESULT_ROOT = ROOT / "results"

# ANSI colors for CLI output
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
USE_COLOR = sys.stdout.isatty()
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _color(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{RESET}"


def _format_percent(value: float) -> str:
    if value >= 90:
        color = GREEN
    elif value >= 50:
        color = YELLOW
    else:
        color = RED
    return _color(f"{value:.2f}%", color)


def _format_metadata_flag(flag: bool) -> str:
    color = GREEN if flag else RED
    text = "yes" if flag else "no"
    return _color(text, color)


def format_percent_plain(value: float) -> str:
    return f"{value:.2f}%"


def format_percent_display(value: float) -> str:
    if USE_COLOR:
        return _format_percent(value)
    return format_percent_plain(value)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def format_status_text(status: str) -> str:
    if not status:
        status = "-"
    if not USE_COLOR:
        return status
    lowered = status.lower()
    if "ok" in lowered:
        color = GREEN
    elif any(word in lowered for word in ("pragma", "no_ethdebug", "compiler_unavailable")):
        color = YELLOW
    else:
        color = RED
    return _color(status, color)


def compiler_display_id(compiler: CompilerConfig) -> str:
    if compiler.kind == "solc" and compiler.via_ir:
        return f"{compiler.compiler_id}-via-ir"
    return compiler.compiler_id


def print_summary_tables(
    contracts: Sequence[ContractConfig],
    compilers: Sequence[CompilerConfig],
    summary_map: Dict[str, Dict[str, Dict[str, object]]],
) -> None:
    if not contracts or not compilers:
        return

    compiler_ids = [compiler.compiler_id for compiler in compilers]
    compiler_labels = [compiler_display_id(compiler) for compiler in compilers]
    totals: Dict[str, Dict[str, object]] = {
        cid: {
            'line_sum': 0.0,
            'var_sum': 0.0,
            'count': 0,
            'statuses': {
                'ok': 0,
                'pragma_incompatible': 0,
                'no_ethdebug_support': 0,
                'compiler_unavailable': 0,
                'failed': 0,
                'other': 0,
            },
        }
        for cid in compiler_ids
    }

    for contract in contracts:
        entries = summary_map.get(contract.contract_id, {})
        for cid in compiler_ids:
            entry = entries.get(cid)
            if not entry:
                continue
            totals[cid]['line_sum'] += float(entry.get('coverage', 0.0))
            totals[cid]['var_sum'] += float(entry.get('variable_coverage_percent', 0.0))
            totals[cid]['count'] += 1
            status = str(entry.get('status', ''))
            key = status if status in totals[cid]['statuses'] else 'other'
            totals[cid]['statuses'][key] += 1

    print(f"\nAnalyzed {len(contracts)} contracts.")

    print("\nLine Coverage Averages:")
    for cid, label in zip(compiler_ids, compiler_labels):
        data = totals[cid]
        avg = data['line_sum'] / data['count'] if data['count'] else 0.0
        print(f"  * {label}: {format_percent_display(avg)}")

    print("\nVariable Location Coverage Averages:")
    for cid, label in zip(compiler_ids, compiler_labels):
        data = totals[cid]
        avg = data['var_sum'] / data['count'] if data['count'] else 0.0
        print(f"  * {label}: {format_percent_display(avg)}")





def parse_version(version: str) -> Tuple[int, int, int]:
    parts = version.split(".")
    major = int(parts[0] or 0)
    minor = int(parts[1] or 0) if len(parts) > 1 else 0
    patch = int(parts[2] or 0) if len(parts) > 2 else 0
    return major, minor, patch


def version_in_range(version: str, minimum: Optional[str], maximum: Optional[str]) -> bool:
    parsed = parse_version(version)
    if minimum and parsed < parse_version(minimum):
        return False
    if maximum and parsed > parse_version(maximum):
        return False
    return True


@dataclass
class ContractConfig:
    """Metadata describing a benchmark contract."""

    contract_id: str
    project: str
    label: str
    repo: str
    source: str
    contract_name: str
    min_solc: Optional[str] = None
    max_solc: Optional[str] = None

    def source_path(self) -> Path:
        return ROOT / self.repo / self.source


@dataclass
class CompilerConfig:
    """Description of a compiler variant to benchmark."""

    compiler_id: str
    kind: str  # solc, placeholder
    description: str
    version: Optional[str] = None
    notes: str = ""
    via_ir: bool = True
    emit_ethdebug: bool = True
    extra_args: Sequence[str] = field(default_factory=tuple)
    supports_ethdebug: bool = True


CONTRACTS: Sequence[ContractConfig] = (
    ContractConfig(
        contract_id="uniswap-v2-pair",
        project="Uniswap",
        label="Uniswap V2 Pair",
        repo="v2-core",
        source="contracts/UniswapV2Pair.sol",
        contract_name="UniswapV2Pair",
        min_solc="0.5.16",
        max_solc="0.5.16",
    ),
    ContractConfig(
        contract_id="erc20-mock",
        project="ERC20",
        label="OpenZeppelin ERC20Mock",
        repo="openzeppelin-contracts",
        source="contracts/mocks/token/ERC20Mock.sol",
        contract_name="ERC20Mock",
        min_solc="0.8.20",
    ),
    ContractConfig(
        contract_id="openzeppelin-vesting-wallet",
        project="OpenZeppelin",
        label="OpenZeppelin VestingWallet",
        repo="openzeppelin-contracts",
        source="contracts/finance/VestingWallet.sol",
        contract_name="VestingWallet",
        min_solc="0.8.20",
    ),
    ContractConfig(
        contract_id="offchainlabs-osp",
        project="OffchainLabs",
        label="Nitro OneStepProofEntry",
        repo="nitro-contracts",
        source="src/osp/OneStepProofEntry.sol",
        contract_name="OneStepProofEntry",
        min_solc="0.8.0",
    ),
    ContractConfig(
        contract_id="aave-l2-encoder",
        project="Aave V3",
        label="Aave L2Encoder",
        repo="aave-v3-core",
        source="contracts/misc/L2Encoder.sol",
        contract_name="L2Encoder",
        min_solc="0.8.10",
    ),
)


COMPILERS: Sequence[CompilerConfig] = (
    CompilerConfig(
        compiler_id="solc-0.8.30",
        kind="solc",
        description="solc 0.8.30",
        version="0.8.30",
        notes="default/latest",
    ),
    CompilerConfig(
        compiler_id="solc-0.8.29",
        kind="solc",
        description="solc 0.8.29",
        version="0.8.29",
        notes="first version with ethdebug",
    ),
    CompilerConfig(
        compiler_id="solc-0.8.30-legacy",
        kind="solc",
        description="solc 0.8.30 legacy pipeline (no --via-ir)",
        version="0.8.30",
        notes="Expect ethdebug failure",
        via_ir=False,
    ),
    CompilerConfig(
        compiler_id="solc-0.8.29-legacy",
        kind="solc",
        description="solc 0.8.29 legacy pipeline (no --via-ir)",
        version="0.8.29",
        notes="Expect ethdebug failure",
        via_ir=False,
    ),
    CompilerConfig(
        compiler_id="solx",
        kind="placeholder",
        description="solx (no ethdebug support yet)",
    ),
    CompilerConfig(
        compiler_id="solar",
        kind="placeholder",
        description="solar (no ethdebug support yet)",
    ),
)


def create_dynamic_solc_config(compiler_id: str) -> Optional[CompilerConfig]:
    legacy = compiler_id.endswith("-legacy")
    base_id = compiler_id[:-7] if legacy else compiler_id
    m = re.match(r"solc-([0-9]+\.[0-9]+\.[0-9]+)", base_id)
    if not m:
        return None
    version = m.group(1)
    supports_ethdebug = parse_version(version) >= parse_version("0.8.29")
    description = f"solc {version}{' legacy pipeline (no --via-ir)' if legacy else ''}"
    return CompilerConfig(
        compiler_id=compiler_id,
        kind="solc",
        description=description,
        version=version,
        notes="auto-detected",
        via_ir=not legacy,
        emit_ethdebug=not legacy and supports_ethdebug,
        supports_ethdebug=supports_ethdebug,
    )


class BenchmarkError(Exception):
    pass


def run(cmd: Sequence[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True)


def detect_solc_versions() -> Dict[str, bool]:
    try:
        result = run(["solc-select", "versions"])
    except FileNotFoundError as exc:
        raise BenchmarkError("solc-select is required to run this benchmark") from exc
    versions: Dict[str, bool] = {}
    if result.returncode != 0:
        raise BenchmarkError(result.stderr.strip() or "failed to list solc-select versions")
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        token = line.split()[0]
        if token[0].isdigit():
            versions[token] = "(current" in line
    return versions


def switch_solc(version: str) -> None:
    result = run(["solc-select", "use", version])
    if result.returncode != 0:
        raise BenchmarkError(result.stderr.strip() or f"failed to select solc {version}")


def ensure_dirs() -> None:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)


def run_ethdebug_stats(ethdebug_file: Path) -> Dict[str, object]:
    result = run(["ethdebug-stats", str(ethdebug_file)])
    if result.returncode != 0:
        raise BenchmarkError(result.stderr.strip() or f"ethdebug-stats failed for {ethdebug_file}")
    return json.loads(result.stdout)


def compile_contract(contract: ContractConfig, compiler: CompilerConfig, build_dir: Path) -> Path:
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)

    source_rel = contract.source
    repo_path = ROOT / contract.repo
    cmd = ["solc"]
    if compiler.via_ir:
        cmd.append("--via-ir")
    if compiler.emit_ethdebug:
        cmd.extend(["--debug-info", "ethdebug", "--ethdebug", "--ethdebug-runtime"])
    cmd.extend(["--bin", "--abi", "--overwrite", "-o", str(build_dir)])
    if compiler.extra_args:
        cmd.extend(compiler.extra_args)
    cmd.append(source_rel)
    result = run(cmd, cwd=repo_path)
    log_path = build_dir / "compile.log"
    log_path.write_text(result.stdout + "\n" + result.stderr)
    if result.returncode != 0:
        raise BenchmarkError(result.stderr.strip() or f"solc failed for {contract.contract_id}")
    runtime_file = build_dir / f"{contract.contract_name}_ethdebug-runtime.json"
    if runtime_file.exists():
        return runtime_file
    fallback = build_dir / f"{contract.contract_name}_ethdebug.json"
    if fallback.exists():
        return fallback
    raise BenchmarkError(f"ethdebug runtime file not produced for {contract.contract_name}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run ethdebug coverage benchmarks")
    parser.add_argument(
        "--compilers",
        nargs="*",
        default=[cfg.compiler_id for cfg in COMPILERS],
        help="Subset of compilers to run (default: all)",
    )
    parser.add_argument(
        "--contracts",
        nargs="*",
        help="Subset of contract ids to benchmark",
    )
    parser.add_argument(
        "--timestamp",
        default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S"),
        help="Timestamp label used for output files",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop on first failure",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-contract logs (default: show summary table)",
    )
    args = parser.parse_args(argv)

    ensure_dirs()

    contract_map = {c.contract_id: c for c in CONTRACTS}
    compiler_map = {c.compiler_id: c for c in COMPILERS}

    selected_contracts: List[ContractConfig]
    if args.contracts:
        missing = [cid for cid in args.contracts if cid not in contract_map]
        if missing:
            parser.error(f"Unknown contract ids: {', '.join(missing)}")
        selected_contracts = [contract_map[cid] for cid in args.contracts]
    else:
        selected_contracts = list(CONTRACTS)

    missing_compilers: List[str] = []
    for cid in args.compilers:
        if cid not in compiler_map:
            dynamic = create_dynamic_solc_config(cid)
            if dynamic:
                compiler_map[cid] = dynamic
            else:
                missing_compilers.append(cid)
    if missing_compilers:
        parser.error(f"Unknown compiler ids: {', '.join(missing_compilers)}")

    selected_compilers = [compiler_map[cid] for cid in args.compilers]

    installed_versions = detect_solc_versions()
    current_solc = None

    rows: List[Dict[str, object]] = []
    summary_map: Dict[str, Dict[str, Dict[str, object]]] = {}

    for compiler in selected_compilers:
        if args.verbose:
            header = f"=== Running compiler {compiler_display_id(compiler)} ({compiler.description}) ==="
            print("\n" + _color(header, CYAN))
        compiler_available = True
        if compiler.kind == "solc":
            assert compiler.version
            if compiler.version not in installed_versions:
                if args.verbose:
                    print(f" - Skipping {compiler.compiler_id}: version not installed via solc-select")
                compiler_available = False
            else:
                if current_solc != compiler.version:
                    try:
                        switch_solc(compiler.version)
                    except BenchmarkError as exc:
                        if args.verbose:
                            print(f" - Failed to switch solc: {exc}")
                        compiler_available = False
                    current_solc = compiler.version
        elif compiler.kind == "placeholder":
            compiler_available = False
        else:
            if args.verbose:
                print(f" - Unknown compiler kind {compiler.kind}")
            compiler_available = False

        for contract in selected_contracts:
            result_entry: Dict[str, object] = {
                "compiler_id": compiler.compiler_id,
                "compiler_description": compiler.description,
                "compiler_version": compiler.version,
                "contract_id": contract.contract_id,
                "project": contract.project,
                "label": contract.label,
                "contract_name": contract.contract_name,
                "repo": contract.repo,
                "source": contract.source,
                "coverage": 0.0,
                "variable_metadata_present": 0,
                "variable_coverage_percent": 0.0,
                "status": "skipped",
                "notes": "",
            }
            rows.append(result_entry)
            summary_map.setdefault(contract.contract_id, {})[compiler.compiler_id] = result_entry

            if compiler.kind == "placeholder":
                if contract.min_solc and contract.max_solc and contract.min_solc == contract.max_solc:
                    min_note = contract.min_solc
                    result_entry["status"] = "pragma_incompatible"
                    result_entry["notes"] = f"requires solc {min_note}"
                    message = "placeholder compiler cannot satisfy locked pragma"
                else:
                    result_entry["status"] = "no_ethdebug_support"
                    result_entry["notes"] = compiler.description
                    message = "placeholder compiler -> coverage 0.0"
                if args.verbose:
                    print(
                        f" - {_color(contract.contract_id, CYAN)}: {message}"
                    )
                summary_map.setdefault(contract.contract_id, {})[compiler.compiler_id] = result_entry
                continue


            if not compiler_available:
                result_entry["status"] = "compiler_unavailable"
                result_entry["notes"] = "compiler not installed"
                if args.verbose:
                    print(
                        f" - {_color(contract.contract_id, CYAN)}: compiler unavailable"
                    )
                continue

            if contract.min_solc and compiler.version and not version_in_range(compiler.version, contract.min_solc, contract.max_solc):
                result_entry["status"] = "pragma_incompatible"
                min_note = contract.min_solc if contract.min_solc == contract.max_solc else f">= {contract.min_solc}"
                result_entry["notes"] = f"requires solc {min_note}"
                if args.verbose:
                    print(
                        f" - {_color(contract.contract_id, CYAN)}: incompatible pragma -> coverage 0.0"
                    )
                continue

            if compiler.kind == "solc" and not compiler.supports_ethdebug:
                result_entry["status"] = "no_ethdebug_support"
                result_entry["notes"] = f"solc {compiler.version} lacks ethdebug support"
                zero_cov = _format_percent(0.0)
                if args.verbose:
                    print(
                        f" - {_color(contract.contract_id, CYAN)}: solc {compiler.version} has no ethdebug -> line coverage {zero_cov} | variable location coverage {zero_cov}"
                    )
                continue

            build_dir = ARTIFACT_ROOT / compiler.compiler_id / contract.contract_id
            try:
                ethdebug_file = compile_contract(contract, compiler, build_dir)
                stats = run_ethdebug_stats(ethdebug_file)
            except BenchmarkError as exc:
                message = str(exc)
                lowered = message.lower()
                if "only be selected, if --via-ir was specified" in lowered:
                    result_entry["status"] = "no_ethdebug_support"
                    result_entry["notes"] = message
                else:
                    result_entry["status"] = "failed"
                    result_entry["notes"] = message
                zero_cov = _format_percent(0.0)
                if args.verbose:
                    print(
                        f" - {_color(contract.contract_id, CYAN)}: {result_entry['status'].upper()} ({message}) | line coverage {zero_cov} | variable location coverage {zero_cov}"
                    )
                if args.fail_fast:
                    return 1
                continue
            result_entry["status"] = "ok"
            result_entry["coverage"] = float(stats.get("source_coverage_percent", 0.0))
            result_entry["variable_metadata_present"] = (
                1 if stats.get("variable_metadata_present") else 0
            )
            result_entry["variable_coverage_percent"] = float(
                stats.get("variable_coverage_percent", 0.0)
            )
            result_entry["notes"] = str(ethdebug_file.relative_to(ROOT))
            result_entry["stats"] = stats
            if args.verbose:
                line_cov = _format_percent(result_entry["coverage"])
                var_cov = _format_percent(result_entry["variable_coverage_percent"])
                print(
                    " - {cid}: {name} | line coverage {line_cov} | variable location coverage {var_cov}".format(
                        cid=_color(contract.contract_id, CYAN),
                        name=contract.contract_name,
                        line_cov=line_cov,
                        var_cov=var_cov,
                    )
                )

    if not args.verbose:
        print_summary_tables(selected_contracts, selected_compilers, summary_map)

    timestamp = args.timestamp
    summary_json = RESULT_ROOT / f"benchmark_{timestamp}.json"
    summary_csv = RESULT_ROOT / f"benchmark_{timestamp}.csv"
    latest_json = RESULT_ROOT / "latest.json"
    latest_csv = RESULT_ROOT / "latest.csv"

    summary_json.write_text(json.dumps(rows, indent=2))
    summary_csv.parent.mkdir(parents=True, exist_ok=True)
    with summary_csv.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "compiler_id",
                "contract_id",
                "project",
                "label",
                "contract_name",
                "repo",
                "source",
                "coverage",
                "variable_metadata_present",
                "variable_coverage_percent",
                "status",
                "notes",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in writer.fieldnames})

    latest_json.write_text(summary_json.read_text())
    latest_csv.write_text(summary_csv.read_text())
    print(f"\nWrote {summary_json} and {summary_csv}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as exc:
        print(f"Benchmark setup error: {exc}", file=sys.stderr)
        raise SystemExit(1)
