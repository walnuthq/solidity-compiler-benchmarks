#!/usr/bin/env python3
"""MLIR pipeline benchmark for Solidity compiler.

Tests MLIR compilation across curated contracts from target repositories:
- smart-contract-security-pitfalls (OffchainLabs)
- lil-web3, erc20, solmate (future)

Tracks compilation success/failure and categorizes errors to identify
CFG patterns not yet supported in the MLIR frontend.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Set

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / "mlir_artifacts"
RESULT_ROOT = ROOT / "mlir_results"

# ANSI colors for CLI output
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


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


@dataclass
class ContractConfig:
    """Metadata describing a contract to test."""
    contract_id: str
    project: str
    label: str
    repo_path: str  # Path relative to ROOT or absolute
    source: str     # Path to .sol file relative to repo_path
    contract_name: str
    min_solc: Optional[str] = None
    max_solc: Optional[str] = None
    # Dependencies/imports needed
    import_paths: Sequence[str] = field(default_factory=list)
    remappings: Dict[str, str] = field(default_factory=dict)

    def source_path(self, base_path: Optional[Path] = None) -> Path:
        """Get the full path to the source file."""
        repo = Path(self.repo_path)
        if not repo.is_absolute():
            repo = (base_path or ROOT) / self.repo_path
        return repo / self.source


@dataclass
class CompileMode:
    """A compilation mode to test."""
    mode_id: str
    description: str
    flags: Sequence[str]
    expects_output: bool = True  # Does this mode produce output files?
    output_suffix: str = ""      # Expected output file suffix (.bin, etc.)


# Define compilation modes for MLIR testing
COMPILE_MODES: Sequence[CompileMode] = (
    CompileMode(
        mode_id="baseline",
        description="Standard compilation (--bin)",
        flags=["--bin"],
        output_suffix=".bin",
    ),
    CompileMode(
        mode_id="mlir-optimize",
        description="MLIR-optimized compilation",
        flags=["--mlir-optimize", "--bin"],
        output_suffix=".bin",
    ),
    CompileMode(
        mode_id="mlir-print",
        description="Print MLIR dialect",
        flags=["--mlir-optimize", "--print-mlir"],
        expects_output=False,
    ),
    CompileMode(
        mode_id="mlir-analyze",
        description="MLIR security analysis",
        flags=["--mlir-optimize", "--mlir-analyze", "--bin"],
        output_suffix=".bin",
    ),
    CompileMode(
        mode_id="via-ir-optimize",
        description="Standard via-ir with optimizer",
        flags=["--via-ir", "--optimize", "--bin"],
        output_suffix=".bin",
    ),
)


# Error categories for tracking unsupported features
# Order matters - more specific patterns should come first
ERROR_CATEGORIES = {
    # MLIR-specific errors
    "mlir_type_mismatch": re.compile(r"must be Solidity .* type, but got", re.I),
    "mlir_parent_op": re.compile(r"expects parent op", re.I),
    "mlir_verifier": re.compile(r"(?:MLIR verification|verifier failed|dialect)", re.I),
    "mlir_region": re.compile(r"(?:region|block argument|terminator)", re.I),
    # Solidity/Yul errors
    "yul_internal": re.compile(r"(?:YulStack|Failed to find object)", re.I),
    "import_error": re.compile(r"(?:Source.*not found|File not found|cannot open)", re.I),
    "type_error": re.compile(r"(?:type mismatch|unsupported type|cannot convert)", re.I),
    "unimplemented": re.compile(r"(?:Unimplemented|Not implemented|TODO)", re.I),
    "cfg_error": re.compile(r"(?:control flow|CFG)", re.I),
    "ast_error": re.compile(r"(?:AST|node|expression|statement)", re.I),
    "syntax_error": re.compile(r"(?:syntax|parse|unexpected|expected)", re.I),
}


def categorize_error(stderr: str) -> Tuple[str, str]:
    """Categorize an error message and extract the relevant portion."""
    for category, pattern in ERROR_CATEGORIES.items():
        if pattern.search(stderr):
            # Extract the most relevant error line
            for line in stderr.splitlines():
                if pattern.search(line) or "error" in line.lower():
                    return category, line.strip()[:200]
            return category, stderr[:200].strip()
    return "unknown", stderr[:200].strip()


def run(cmd: Sequence[str], cwd: Optional[Path] = None,
        timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run a command and capture output."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, check=False, capture_output=True,
            text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr="TIMEOUT"
        )


def detect_solc(solc_path: Optional[str] = None) -> Tuple[Optional[Path], Optional[str]]:
    """Find solc binary and get its version."""
    if solc_path:
        path = Path(solc_path)
        if path.exists():
            result = run([str(path), "--version"])
            if result.returncode == 0:
                # Extract version from output
                match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", result.stdout)
                version = match.group(1) if match else "unknown"
                return path, version

    # Try common locations
    for candidate in ["solc", "build/solc/solc", "../solidity/build/solc/solc"]:
        path = Path(candidate)
        if not path.is_absolute():
            path = ROOT / candidate
        if path.exists():
            result = run([str(path), "--version"])
            if result.returncode == 0:
                match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", result.stdout)
                version = match.group(1) if match else "unknown"
                return path, version

    # Try system solc
    result = run(["which", "solc"])
    if result.returncode == 0:
        path = Path(result.stdout.strip())
        result = run([str(path), "--version"])
        if result.returncode == 0:
            match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", result.stdout)
            version = match.group(1) if match else "unknown"
            return path, version

    return None, None


def compile_contract(
    contract: ContractConfig,
    mode: CompileMode,
    solc_path: Path,
    build_dir: Path,
    base_path: Optional[Path] = None,
) -> Dict[str, object]:
    """Compile a contract with the given mode and return results."""

    result_entry: Dict[str, object] = {
        "contract_id": contract.contract_id,
        "project": contract.project,
        "label": contract.label,
        "mode_id": mode.mode_id,
        "mode_description": mode.description,
        "status": "pending",
        "error_category": "",
        "error_message": "",
        "output_size": 0,
        "mlir_output": "",
    }

    source_path = contract.source_path(base_path)
    if not source_path.exists():
        result_entry["status"] = "source_not_found"
        result_entry["error_message"] = f"Source file not found: {source_path}"
        return result_entry

    # Build command
    cmd = [str(solc_path)]
    cmd.extend(mode.flags)

    # Add remappings
    for name, path in contract.remappings.items():
        cmd.append(f"{name}={path}")

    # Add include paths
    for inc_path in contract.import_paths:
        cmd.extend(["--include-path", inc_path])

    # Add base path for the repo
    repo_path = source_path.parent
    if contract.repo_path:
        repo_base = Path(contract.repo_path)
        if not repo_base.is_absolute():
            repo_base = (base_path or ROOT) / contract.repo_path
        cmd.extend(["--base-path", str(repo_base)])

    # Add output directory for modes that produce files
    if mode.expects_output:
        if build_dir.exists():
            shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-o", str(build_dir), "--overwrite"])

    cmd.append(str(source_path))

    # Run compilation
    proc_result = run(cmd, timeout=120)

    # Save command for debugging
    result_entry["command"] = " ".join(cmd)

    if proc_result.returncode != 0:
        category, message = categorize_error(proc_result.stderr)
        result_entry["status"] = "failed"
        result_entry["error_category"] = category
        result_entry["error_message"] = message
        result_entry["full_stderr"] = proc_result.stderr[:2000]
        return result_entry

    # Success - check output
    result_entry["status"] = "ok"

    if mode.mode_id == "mlir-print":
        # MLIR output goes to stderr
        result_entry["mlir_output"] = proc_result.stderr[:5000]
        result_entry["output_size"] = len(proc_result.stderr)
    elif mode.expects_output:
        # Check for output files
        output_files = list(build_dir.glob(f"*{mode.output_suffix}"))
        if output_files:
            total_size = sum(f.stat().st_size for f in output_files)
            result_entry["output_size"] = total_size
            result_entry["output_files"] = [str(f.name) for f in output_files]

    return result_entry


def discover_contracts(
    project_path: Path,
    project_name: str,
    pattern: str = "**/*.sol"
) -> List[ContractConfig]:
    """Discover contracts in a project directory."""
    contracts = []
    for sol_file in project_path.glob(pattern):
        # Skip test files and libraries
        rel_path = sol_file.relative_to(project_path)
        if "test" in str(rel_path).lower() or "lib/" in str(rel_path):
            continue

        # Extract contract name from filename
        contract_name = sol_file.stem
        contract_id = f"{project_name}-{contract_name}".lower().replace("_", "-")

        contracts.append(ContractConfig(
            contract_id=contract_id,
            project=project_name,
            label=contract_name,
            repo_path=str(project_path),
            source=str(rel_path),
            contract_name=contract_name,
        ))

    return contracts


# Pre-defined contracts for testing
SECURITY_PITFALLS_CONTRACTS: Sequence[ContractConfig] = (
    ContractConfig(
        contract_id="pitfalls-noaccess",
        project="security-pitfalls",
        label="NoAccess - Missing access control",
        repo_path="../smart-contract-security-pitfalls",
        source="src/access/NoAccess.sol",
        contract_name="NoAccess",
    ),
    ContractConfig(
        contract_id="pitfalls-vulnerable-vault",
        project="security-pitfalls",
        label="VulnerableVault - Reentrancy bug",
        repo_path="../smart-contract-security-pitfalls",
        source="src/reentrancy/VulnerableVault.sol",
        contract_name="VulnerableVault",
    ),
    ContractConfig(
        contract_id="pitfalls-safe-vault",
        project="security-pitfalls",
        label="SafeVault - Fixed reentrancy",
        repo_path="../smart-contract-security-pitfalls",
        source="src/reentrancy/SafeVault.sol",
        contract_name="SafeVault",
        remappings={"@openzeppelin/": "lib/openzeppelin-contracts/"},
    ),
    ContractConfig(
        contract_id="pitfalls-underflow",
        project="security-pitfalls",
        label="UnderflowDemo - Unchecked arithmetic",
        repo_path="../smart-contract-security-pitfalls",
        source="src/underflow/UnderflowDemo.sol",
        contract_name="UnderflowDemo",
    ),
)

# Solmate contracts - gas-optimized building blocks
SOLMATE_CONTRACTS: Sequence[ContractConfig] = (
    # Tokens
    ContractConfig(
        contract_id="solmate-erc20",
        project="solmate",
        label="ERC20 - Gas-optimized ERC20",
        repo_path="solmate",
        source="src/tokens/ERC20.sol",
        contract_name="ERC20",
    ),
    ContractConfig(
        contract_id="solmate-erc721",
        project="solmate",
        label="ERC721 - Gas-optimized ERC721",
        repo_path="solmate",
        source="src/tokens/ERC721.sol",
        contract_name="ERC721",
    ),
    ContractConfig(
        contract_id="solmate-erc1155",
        project="solmate",
        label="ERC1155 - Gas-optimized ERC1155",
        repo_path="solmate",
        source="src/tokens/ERC1155.sol",
        contract_name="ERC1155",
    ),
    ContractConfig(
        contract_id="solmate-erc4626",
        project="solmate",
        label="ERC4626 - Tokenized vault",
        repo_path="solmate",
        source="src/tokens/ERC4626.sol",
        contract_name="ERC4626",
    ),
    ContractConfig(
        contract_id="solmate-erc6909",
        project="solmate",
        label="ERC6909 - Multi-token",
        repo_path="solmate",
        source="src/tokens/ERC6909.sol",
        contract_name="ERC6909",
    ),
    ContractConfig(
        contract_id="solmate-weth",
        project="solmate",
        label="WETH - Wrapped Ether",
        repo_path="solmate",
        source="src/tokens/WETH.sol",
        contract_name="WETH",
    ),
    # Auth
    ContractConfig(
        contract_id="solmate-owned",
        project="solmate",
        label="Owned - Simple ownership",
        repo_path="solmate",
        source="src/auth/Owned.sol",
        contract_name="Owned",
    ),
    ContractConfig(
        contract_id="solmate-auth",
        project="solmate",
        label="Auth - Flexible authority",
        repo_path="solmate",
        source="src/auth/Auth.sol",
        contract_name="Auth",
    ),
    # Utils
    ContractConfig(
        contract_id="solmate-fixedpoint",
        project="solmate",
        label="FixedPointMathLib - Math utils",
        repo_path="solmate",
        source="src/utils/FixedPointMathLib.sol",
        contract_name="FixedPointMathLib",
    ),
    ContractConfig(
        contract_id="solmate-safecast",
        project="solmate",
        label="SafeCastLib - Safe casting",
        repo_path="solmate",
        source="src/utils/SafeCastLib.sol",
        contract_name="SafeCastLib",
    ),
    ContractConfig(
        contract_id="solmate-safetransfer",
        project="solmate",
        label="SafeTransferLib - Safe transfers",
        repo_path="solmate",
        source="src/utils/SafeTransferLib.sol",
        contract_name="SafeTransferLib",
    ),
    ContractConfig(
        contract_id="solmate-reentrancyguard",
        project="solmate",
        label="ReentrancyGuard - Reentrancy protection",
        repo_path="solmate",
        source="src/utils/ReentrancyGuard.sol",
        contract_name="ReentrancyGuard",
    ),
    ContractConfig(
        contract_id="solmate-merkleproof",
        project="solmate",
        label="MerkleProofLib - Merkle proofs",
        repo_path="solmate",
        source="src/utils/MerkleProofLib.sol",
        contract_name="MerkleProofLib",
    ),
    ContractConfig(
        contract_id="solmate-create3",
        project="solmate",
        label="CREATE3 - Deterministic deploy",
        repo_path="solmate",
        source="src/utils/CREATE3.sol",
        contract_name="CREATE3",
    ),
    ContractConfig(
        contract_id="solmate-sstore2",
        project="solmate",
        label="SSTORE2 - Efficient storage",
        repo_path="solmate",
        source="src/utils/SSTORE2.sol",
        contract_name="SSTORE2",
    ),
    ContractConfig(
        contract_id="solmate-libstring",
        project="solmate",
        label="LibString - String utils",
        repo_path="solmate",
        source="src/utils/LibString.sol",
        contract_name="LibString",
    ),
    ContractConfig(
        contract_id="solmate-signedwadmath",
        project="solmate",
        label="SignedWadMath - Signed math",
        repo_path="solmate",
        source="src/utils/SignedWadMath.sol",
        contract_name="SignedWadMath",
    ),
    ContractConfig(
        contract_id="solmate-bytes32addr",
        project="solmate",
        label="Bytes32AddressLib - Address utils",
        repo_path="solmate",
        source="src/utils/Bytes32AddressLib.sol",
        contract_name="Bytes32AddressLib",
    ),
)

# lil-web3 contracts - minimal implementations
# These contracts import from solmate, so need remappings
LIL_WEB3_CONTRACTS: Sequence[ContractConfig] = (
    ContractConfig(
        contract_id="lilweb3-ens",
        project="lil-web3",
        label="LilENS - Simple namespace",
        repo_path="lil-web3",
        source="src/LilENS.sol",
        contract_name="LilENS",
    ),
    ContractConfig(
        contract_id="lilweb3-flashloan",
        project="lil-web3",
        label="LilFlashloan - Flash loans",
        repo_path="lil-web3",
        source="src/LilFlashloan.sol",
        contract_name="LilFlashloan",
        remappings={"solmate/": "lib/solmate/src/"},
    ),
    ContractConfig(
        contract_id="lilweb3-fractional",
        project="lil-web3",
        label="LilFractional - NFT fractionalization",
        repo_path="lil-web3",
        source="src/LilFractional.sol",
        contract_name="LilFractional",
        remappings={"solmate/": "lib/solmate/src/"},
    ),
    ContractConfig(
        contract_id="lilweb3-gnosis",
        project="lil-web3",
        label="LilGnosis - Multisig wallet",
        repo_path="lil-web3",
        source="src/LilGnosis.sol",
        contract_name="LilGnosis",
    ),
    ContractConfig(
        contract_id="lilweb3-juicebox",
        project="lil-web3",
        label="LilJuicebox - Crowdfunding",
        repo_path="lil-web3",
        source="src/LilJuicebox.sol",
        contract_name="LilJuicebox",
        remappings={"solmate/": "lib/solmate/src/"},
    ),
    ContractConfig(
        contract_id="lilweb3-opensea",
        project="lil-web3",
        label="LilOpenSea - NFT marketplace",
        repo_path="lil-web3",
        source="src/LilOpenSea.sol",
        contract_name="LilOpenSea",
        remappings={"solmate/": "lib/solmate/src/"},
    ),
    ContractConfig(
        contract_id="lilweb3-superfluid",
        project="lil-web3",
        label="LilSuperfluid - Money streaming",
        repo_path="lil-web3",
        source="src/LilSuperfluid.sol",
        contract_name="LilSuperfluid",
        remappings={"solmate/": "lib/solmate/src/"},
    ),
)

# Maple Labs ERC20 - production ERC20
MAPLE_ERC20_CONTRACTS: Sequence[ContractConfig] = (
    ContractConfig(
        contract_id="maple-erc20",
        project="maple-labs",
        label="ERC20 - Production ERC20",
        repo_path="maple-erc20",
        source="contracts/ERC20.sol",
        contract_name="ERC20",
    ),
)

# Contracts from the solidity/test/mlir directory (known to work)
MLIR_TEST_CONTRACTS: Sequence[ContractConfig] = (
    ContractConfig(
        contract_id="mlir-factorial",
        project="mlir-tests",
        label="Factorial - Storage caching example",
        repo_path="../solidity/test/mlir",
        source="factorial.sol",
        contract_name="FactorialStorage",
    ),
    ContractConfig(
        contract_id="mlir-arithmetic",
        project="mlir-tests",
        label="Arithmetic operations",
        repo_path="../solidity/test/mlir",
        source="arithmetic_operations.sol",
        contract_name="ArithmeticTest",
    ),
    ContractConfig(
        contract_id="mlir-control-flow",
        project="mlir-tests",
        label="Control flow patterns",
        repo_path="../solidity/test/mlir",
        source="control_flow.sol",
        contract_name="Test",
    ),
    ContractConfig(
        contract_id="mlir-type-system",
        project="mlir-tests",
        label="Type system coverage",
        repo_path="../solidity/test/mlir",
        source="type_system.sol",
        contract_name="TypeTest",
    ),
)


def print_summary(results: List[Dict[str, object]], modes: Sequence[CompileMode]) -> None:
    """Print a summary table of results."""

    # Group by contract
    by_contract: Dict[str, Dict[str, Dict[str, object]]] = {}
    for r in results:
        cid = r["contract_id"]
        mid = r["mode_id"]
        by_contract.setdefault(cid, {})[mid] = r

    # Calculate column widths - include project name in display
    def get_display_name(r: Dict[str, object]) -> str:
        return f"{r['label']} ({r['project']})"

    contract_width = max(len(get_display_name(r)) for r in results) + 2
    mode_width = max(len(m.mode_id) for m in modes) + 2

    # Header
    header = f"{'Contract':<{contract_width}}"
    for mode in modes:
        header += f" | {mode.mode_id:<{mode_width}}"
    print("\n" + _color("=" * len(strip_ansi(header)), CYAN))
    print(_color("MLIR Compilation Test Results", BOLD))
    print(_color("=" * len(strip_ansi(header)), CYAN))
    print(header)
    print("-" * len(strip_ansi(header)))

    # Rows
    for cid, mode_results in by_contract.items():
        first_result = next(iter(mode_results.values()))
        display_name = get_display_name(first_result)
        row = f"{display_name:<{contract_width}}"
        for mode in modes:
            r = mode_results.get(mode.mode_id, {})
            status = r.get("status", "-")
            if status == "ok":
                cell = _color("OK", GREEN)
            elif status == "failed":
                cell = _color("FAILED", RED)
            elif status == "source_not_found":
                cell = _color("MISSING", YELLOW)
            else:
                cell = _color(status, YELLOW)
            row += f" | {cell:<{mode_width + (len(cell) - len(strip_ansi(cell)))}}"
        print(row)

    print("-" * len(strip_ansi(header)))

    # Summary stats
    total = len(results)
    ok = sum(1 for r in results if r["status"] == "ok")
    failed = sum(1 for r in results if r["status"] == "failed")
    other = total - ok - failed

    print(f"\nTotal: {total} | {_color(f'OK: {ok}', GREEN)} | "
          f"{_color(f'Failed: {failed}', RED)} | Other: {other}")

    # Print failures with errors and reproduction commands
    failures = [r for r in results if r["status"] == "failed"]
    if failures:
        print("\n" + _color("Failures:", BOLD))
        for r in failures:
            print(f"\n  {r['contract_id']} [{r['mode_id']}]:")
            print(f"    error: {r.get('error_message', 'unknown')}")
            if r.get('command'):
                print(f"    reproduce: {r['command']}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Test MLIR pipeline compilation across contracts"
    )
    parser.add_argument(
        "--solc",
        help="Path to solc binary with MLIR support",
    )
    parser.add_argument(
        "--modes",
        nargs="*",
        default=None,
        help="Subset of modes to test (default: all)",
    )
    parser.add_argument(
        "--contracts",
        nargs="*",
        help="Subset of contract ids to test",
    )
    parser.add_argument(
        "--project-path",
        help="Path to project directory to discover contracts",
    )
    parser.add_argument(
        "--project-name",
        default="custom",
        help="Name for discovered project",
    )
    parser.add_argument(
        "--base-path",
        help="Base path for resolving relative repo paths",
    )
    parser.add_argument(
        "--include-mlir-tests",
        action="store_true",
        help="Include contracts from solidity/test/mlir",
    )
    parser.add_argument(
        "--only-mlir-modes",
        action="store_true",
        help="Only test MLIR-specific modes (skip baseline)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output including errors",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop on first failure",
    )
    parser.add_argument(
        "--timestamp",
        default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S"),
        help="Timestamp for output files",
    )
    args = parser.parse_args(argv)

    # Find solc
    solc_path, solc_version = detect_solc(args.solc)
    if not solc_path:
        print(_color("Error: Could not find solc binary", RED), file=sys.stderr)
        print("Use --solc to specify the path to your MLIR-enabled solc build",
              file=sys.stderr)
        return 1

    print(f"Using solc: {solc_path} (version: {solc_version})")

    # Determine base path
    base_path = Path(args.base_path) if args.base_path else ROOT

    # Select contracts
    all_contracts: List[ContractConfig] = []
    all_contracts.extend(SECURITY_PITFALLS_CONTRACTS)
    all_contracts.extend(SOLMATE_CONTRACTS)
    all_contracts.extend(LIL_WEB3_CONTRACTS)
    all_contracts.extend(MAPLE_ERC20_CONTRACTS)

    if args.include_mlir_tests:
        all_contracts.extend(MLIR_TEST_CONTRACTS)

    if args.project_path:
        discovered = discover_contracts(
            Path(args.project_path),
            args.project_name
        )
        all_contracts.extend(discovered)
        print(f"Discovered {len(discovered)} contracts in {args.project_path}")

    if args.contracts:
        contract_map = {c.contract_id: c for c in all_contracts}
        missing = [cid for cid in args.contracts if cid not in contract_map]
        if missing:
            print(_color(f"Unknown contract ids: {', '.join(missing)}", RED),
                  file=sys.stderr)
            return 1
        all_contracts = [contract_map[cid] for cid in args.contracts]

    # Select modes
    if args.only_mlir_modes:
        # Exclude mlir-print as it only dumps MLIR, doesn't compile
        selected_modes = [m for m in COMPILE_MODES if "mlir" in m.mode_id and m.mode_id != "mlir-print"]
    elif args.modes:
        mode_map = {m.mode_id: m for m in COMPILE_MODES}
        missing = [mid for mid in args.modes if mid not in mode_map]
        if missing:
            print(_color(f"Unknown mode ids: {', '.join(missing)}", RED),
                  file=sys.stderr)
            return 1
        selected_modes = [mode_map[mid] for mid in args.modes]
    else:
        selected_modes = list(COMPILE_MODES)

    print(f"Testing {len(all_contracts)} contracts with {len(selected_modes)} modes")

    # Create output directories
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)

    # Run tests
    results: List[Dict[str, object]] = []

    for contract in all_contracts:
        if args.verbose:
            print(f"\n{_color(contract.label, CYAN)}:")

        for mode in selected_modes:
            build_dir = ARTIFACT_ROOT / contract.contract_id / mode.mode_id

            result = compile_contract(
                contract, mode, solc_path, build_dir, base_path
            )
            results.append(result)

            if args.verbose:
                status = result["status"]
                if status == "ok":
                    print(f"  {mode.mode_id}: {_color('OK', GREEN)}")
                else:
                    print(f"  {mode.mode_id}: {_color('FAILED', RED)}")
                    if result.get("error_message"):
                        print(f"    {result['error_message'][:100]}")

            if args.fail_fast and result["status"] == "failed":
                print(_color("\nStopping on first failure", RED))
                break

        if args.fail_fast and results and results[-1]["status"] == "failed":
            break

    # Print summary
    print_summary(results, selected_modes)

    # Save results
    timestamp = args.timestamp
    result_json = RESULT_ROOT / f"mlir_bench_{timestamp}.json"
    result_csv = RESULT_ROOT / f"mlir_bench_{timestamp}.csv"
    latest_json = RESULT_ROOT / "mlir_latest.json"
    latest_csv = RESULT_ROOT / "mlir_latest.csv"

    # JSON output
    result_json.write_text(json.dumps(results, indent=2, default=str))

    # CSV output
    fieldnames = [
        "contract_id", "project", "label", "mode_id", "mode_description",
        "status", "error_category", "error_message", "output_size",
    ]
    with result_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    # Copy to latest
    latest_json.write_text(result_json.read_text())
    latest_csv.write_text(result_csv.read_text())

    print(f"\nResults saved to {result_json}")

    # Return non-zero if any failures
    failed_count = sum(1 for r in results if r["status"] == "failed")
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
