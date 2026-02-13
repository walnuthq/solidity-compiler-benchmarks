#!/usr/bin/env python3
"""MLIR pipeline benchmark for Solidity compiler.

Tests MLIR compilation across curated contracts from target repositories:
- smart-contract-security-pitfalls (OffchainLabs)
- lil-web3, erc20, solmate (future)

Tracks compilation success/failure and categorizes errors to identify
CFG patterns not yet supported in the MLIR frontend.

Extended features:
- Code size comparison between solc --via-ir, solc --mlir-optimize, and solx
- Runtime gas comparison using anvil and cast
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
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
from typing import Dict, List, Optional, Sequence, Tuple, Set, Any

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / "mlir_artifacts"
RESULT_ROOT = ROOT / "mlir_results"
GAS_RESULT_ROOT = ROOT / "gas_results"

# ANSI colors for CLI output
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
MAGENTA = "\033[35m"
USE_COLOR = sys.stdout.isatty()
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

# Default Anvil settings
DEFAULT_RPC_URL = "http://127.0.0.1:8545"
DEFAULT_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


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
    # Gas testing configuration
    gas_test_calls: Sequence[Tuple[str, Sequence[str]]] = field(default_factory=list)
    constructor_args: Sequence[str] = field(default_factory=list)
    wrapper_source: Optional[str] = None  # Inline concrete wrapper for abstract contracts

    def source_path(self, base_path: Optional[Path] = None) -> Path:
        """Get the full path to the source file."""
        repo = Path(self.repo_path)
        if not repo.is_absolute():
            repo = (base_path or ROOT) / self.repo_path
        return repo / self.source


@dataclass
class GasTestCase:
    """A test case for gas benchmarking with inline source."""
    test_id: str
    description: str
    source_code: str
    contract_name: str
    test_calls: Sequence[Tuple[str, Sequence[str]]]
    constructor_args: Sequence[str] = field(default_factory=list)
    constructor_sig: Optional[str] = None  # e.g., "constructor(string,string,uint8)"


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


def detect_solx(solx_path: Optional[str] = None) -> Tuple[Optional[Path], Optional[str]]:
    """Find solx binary and get its version."""
    if solx_path:
        path = Path(solx_path)
        if path.exists():
            result = run([str(path), "--version"])
            if result.returncode == 0:
                # solx version format may differ
                match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
                version = match.group(1) if match else "unknown"
                return path, version

    # Try common locations
    for candidate in ["solx", "../solx/solx", "/usr/local/bin/solx"]:
        path = Path(candidate)
        if not path.is_absolute():
            path = ROOT / candidate
        if path.exists():
            result = run([str(path), "--version"])
            if result.returncode == 0:
                match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
                version = match.group(1) if match else "unknown"
                return path, version

    # Try system solx
    result = run(["which", "solx"])
    if result.returncode == 0:
        path = Path(result.stdout.strip())
        result = run([str(path), "--version"])
        if result.returncode == 0:
            match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
            version = match.group(1) if match else "unknown"
            return path, version

    return None, None


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


def deploy_contract(
    bytecode: str,
    rpc_url: str,
    private_key: str,
    constructor_args: Optional[Sequence[str]] = None,
    constructor_sig: Optional[str] = None,
    verbose: bool = False,
) -> Optional[str]:
    """Deploy contract and return address."""
    # Ensure bytecode has 0x prefix
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode

    # Options must come before --create subcommand
    cmd = [
        "cast", "send",
        "--rpc-url", rpc_url,
        "--private-key", private_key,
        "--json",
        "--create", bytecode,
    ]

    # Add constructor signature and args if provided
    if constructor_sig and constructor_args:
        cmd.append(constructor_sig)
        cmd.extend(constructor_args)

    result = run(cmd, timeout=60)

    if result.returncode != 0:
        if verbose:
            print(f"    Deploy error: {result.stderr[:200]}")
        return None

    try:
        data = json.loads(result.stdout)
        return data.get("contractAddress")
    except json.JSONDecodeError:
        if verbose:
            print(f"    Deploy JSON parse error: {result.stdout[:200]}")
        return None


def call_contract(
    address: str,
    signature: str,
    args: Sequence[str],
    rpc_url: str,
    private_key: str,
    verbose: bool = False,
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
        if verbose:
            print(f"    Call error: {result.stderr[:200]}")
        return None

    try:
        data = json.loads(result.stdout)
        gas = data.get("gasUsed")
        # Handle hex or int format
        if isinstance(gas, str):
            if gas.startswith("0x"):
                return int(gas, 16)
            return int(gas)
        return int(gas) if gas else None
    except (json.JSONDecodeError, ValueError) as e:
        if verbose:
            print(f"    Call parse error: {e}, output: {result.stdout[:200]}")
        return None


def get_bytecode_from_output(output_dir: Path, contract_name: str) -> Optional[str]:
    """Extract bytecode from compilation output directory."""
    # Try contract-specific file first
    bin_file = output_dir / f"{contract_name}.bin"
    if bin_file.exists():
        return bin_file.read_text().strip()

    # Try any .bin file
    bin_files = list(output_dir.glob("*.bin"))
    if bin_files:
        # Prefer the largest one (usually the main contract)
        bin_files.sort(key=lambda f: f.stat().st_size, reverse=True)
        return bin_files[0].read_text().strip()

    return None


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

    # Use wrapper source if provided (for abstract contracts)
    actual_source = source_path
    if contract.wrapper_source:
        build_dir.mkdir(parents=True, exist_ok=True)
        wrapper_path = build_dir / f"{contract.contract_name}_wrapper.sol"
        wrapper_path.write_text(contract.wrapper_source)
        actual_source = wrapper_path

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
        if build_dir.exists() and not contract.wrapper_source:
            shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-o", str(build_dir), "--overwrite"])

    cmd.append(str(actual_source))

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
        contract_name="TestERC20",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {ERC20} from "src/tokens/ERC20.sol";\ncontract TestERC20 is ERC20 {\n    constructor() ERC20("Test", "TST", 18) {}\n    function mint(address to, uint256 amount) external { _mint(to, amount); }\n}\n',
    ),
    ContractConfig(
        contract_id="solmate-erc721",
        project="solmate",
        label="ERC721 - Gas-optimized ERC721",
        repo_path="solmate",
        source="src/tokens/ERC721.sol",
        contract_name="TestERC721",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {ERC721} from "src/tokens/ERC721.sol";\ncontract TestERC721 is ERC721 {\n    constructor() ERC721("Test", "TST") {}\n    function tokenURI(uint256) public pure override returns (string memory) { return ""; }\n    function mint(address to, uint256 id) external { _mint(to, id); }\n}\n',
    ),
    ContractConfig(
        contract_id="solmate-erc1155",
        project="solmate",
        label="ERC1155 - Gas-optimized ERC1155",
        repo_path="solmate",
        source="src/tokens/ERC1155.sol",
        contract_name="TestERC1155",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {ERC1155} from "src/tokens/ERC1155.sol";\ncontract TestERC1155 is ERC1155 {\n    function uri(uint256) public pure override returns (string memory) { return ""; }\n    function mint(address to, uint256 id, uint256 amount) external { _mint(to, id, amount, ""); }\n}\n',
    ),
    ContractConfig(
        contract_id="solmate-erc4626",
        project="solmate",
        label="ERC4626 - Tokenized vault",
        repo_path="solmate",
        source="src/tokens/ERC4626.sol",
        contract_name="TestERC4626",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {ERC20} from "src/tokens/ERC20.sol";\nimport {ERC4626} from "src/tokens/ERC4626.sol";\ncontract MockERC20 is ERC20 {\n    constructor() ERC20("Asset", "AST", 18) {}\n    function mint(address to, uint256 amount) external { _mint(to, amount); }\n}\ncontract TestERC4626 is ERC4626 {\n    constructor(ERC20 asset) ERC4626(asset, "Vault", "VLT") {}\n    function totalAssets() public view override returns (uint256) { return asset.balanceOf(address(this)); }\n}\n',
    ),
    ContractConfig(
        contract_id="solmate-erc6909",
        project="solmate",
        label="ERC6909 - Multi-token",
        repo_path="solmate",
        source="src/tokens/ERC6909.sol",
        contract_name="TestERC6909",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {ERC6909} from "src/tokens/ERC6909.sol";\ncontract TestERC6909 is ERC6909 {\n    function mint(address to, uint256 id, uint256 amount) external { _mint(to, id, amount); }\n}\n',
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
        contract_name="TestOwned",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {Owned} from "src/auth/Owned.sol";\ncontract TestOwned is Owned(msg.sender) {}\n',
    ),
    ContractConfig(
        contract_id="solmate-auth",
        project="solmate",
        label="Auth - Flexible authority",
        repo_path="solmate",
        source="src/auth/Auth.sol",
        contract_name="TestAuth",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {Auth, Authority} from "src/auth/Auth.sol";\ncontract TestAuth is Auth(msg.sender, Authority(address(0))) {}\n',
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
        contract_name="TestReentrancyGuard",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport {ReentrancyGuard} from "src/utils/ReentrancyGuard.sol";\ncontract TestReentrancyGuard is ReentrancyGuard {\n    uint256 public value;\n    function protected() external nonReentrant { value = 1; }\n}\n',
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
        contract_name="TestSignedWadMath",
        wrapper_source='// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\nimport "src/utils/SignedWadMath.sol";\ncontract TestSignedWadMath {\n    function testWadMul(int256 x, int256 y) external pure returns (int256) { return wadMul(x, y); }\n    function testWadDiv(int256 x, int256 y) external pure returns (int256) { return wadDiv(x, y); }\n    function testWadExp(int256 x) external pure returns (int256) { return wadExp(x); }\n    function testWadLn(int256 x) external pure returns (int256) { return wadLn(x); }\n}\n',
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
        # Gas test: register and lookup names
        gas_test_calls=[
            ("register(string)", ["testname"]),
            ("lookup(string)", ["testname"]),
        ],
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
        gas_test_calls=[
            ("computeFactorial(uint256)", ["5"]),
            ("computeFactorial(uint256)", ["10"]),
            ("computeFactorial(uint256)", ["20"]),
        ],
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


# Gas test cases with inline source code for quick benchmarking
GAS_TEST_CASES: Sequence[GasTestCase] = (
    GasTestCase(
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
    GasTestCase(
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
    GasTestCase(
        test_id="sum-range",
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
    GasTestCase(
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
    # Wrapper contracts for abstract solmate contracts
    GasTestCase(
        test_id="erc20-wrapper",
        description="ERC20 token wrapper (solmate-style)",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestERC20 {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        unchecked { balanceOf[to] += amount; }
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        unchecked { balanceOf[to] += amount; }
        return true;
    }

    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        unchecked { balanceOf[to] += amount; }
    }

    function burn(address from, uint256 amount) public {
        balanceOf[from] -= amount;
        unchecked { totalSupply -= amount; }
    }
}
''',
        contract_name="TestERC20",
        constructor_args=["TestToken", "TST", "18"],
        constructor_sig="constructor(string,string,uint8)",
        test_calls=[
            ("mint(address,uint256)", ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "1000000000000000000000"]),
            ("transfer(address,uint256)", ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "100000000000000000000"]),
            ("approve(address,uint256)", ["0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "500000000000000000000"]),
            ("balanceOf(address)", ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]),
        ],
    ),
    GasTestCase(
        test_id="erc721-wrapper",
        description="ERC721 NFT wrapper (solmate-style)",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestERC721 {
    string public name;
    string public symbol;
    mapping(uint256 => address) internal _ownerOf;
    mapping(address => uint256) internal _balanceOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function ownerOf(uint256 id) public view returns (address owner) {
        require((owner = _ownerOf[id]) != address(0), "NOT_MINTED");
    }

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "ZERO_ADDRESS");
        return _balanceOf[owner];
    }

    function approve(address spender, uint256 id) public {
        address owner = _ownerOf[id];
        require(msg.sender == owner || isApprovedForAll[owner][msg.sender], "NOT_AUTHORIZED");
        getApproved[id] = spender;
    }

    function setApprovalForAll(address operator, bool approved) public {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 id) public {
        require(from == _ownerOf[id], "WRONG_FROM");
        require(to != address(0), "INVALID_RECIPIENT");
        require(
            msg.sender == from || isApprovedForAll[from][msg.sender] || msg.sender == getApproved[id],
            "NOT_AUTHORIZED"
        );
        unchecked {
            _balanceOf[from]--;
            _balanceOf[to]++;
        }
        _ownerOf[id] = to;
        delete getApproved[id];
    }

    function mint(address to, uint256 id) public {
        require(to != address(0), "INVALID_RECIPIENT");
        require(_ownerOf[id] == address(0), "ALREADY_MINTED");
        unchecked { _balanceOf[to]++; }
        _ownerOf[id] = to;
    }

    function burn(uint256 id) public {
        address owner = _ownerOf[id];
        require(owner != address(0), "NOT_MINTED");
        unchecked { _balanceOf[owner]--; }
        delete _ownerOf[id];
        delete getApproved[id];
    }
}
''',
        contract_name="TestERC721",
        constructor_args=["TestNFT", "TNFT"],
        constructor_sig="constructor(string,string)",
        test_calls=[
            ("mint(address,uint256)", ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "1"]),
            ("mint(address,uint256)", ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "2"]),
            ("mint(address,uint256)", ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "3"]),
            ("approve(address,uint256)", ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "1"]),
            ("transferFrom(address,address,uint256)", ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "2"]),
            ("setApprovalForAll(address,bool)", ["0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "true"]),
        ],
    ),
    GasTestCase(
        test_id="weth-wrapper",
        description="WETH wrapped ether",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestWETH {
    string public name = "Wrapped Ether";
    string public symbol = "WETH";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Deposit(address indexed from, uint256 amount);
    event Withdrawal(address indexed to, uint256 amount);

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }

    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        if (from != msg.sender) {
            uint256 allowed = allowance[from][msg.sender];
            if (allowed != type(uint256).max) {
                allowance[from][msg.sender] = allowed - amount;
            }
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    receive() external payable {
        deposit();
    }
}
''',
        contract_name="TestWETH",
        test_calls=[
            ("approve(address,uint256)", ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "1000000000000000000"]),
            ("transfer(address,uint256)", ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0"]),
        ],
    ),
    GasTestCase(
        test_id="storage-patterns",
        description="Common storage access patterns",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StoragePatterns {
    uint256 public counter;
    uint256[] public values;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    function incrementCounter(uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            counter++;
        }
    }

    function pushValues(uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            values.push(i);
        }
    }

    function updateBalances(address[] calldata accounts, uint256 amount) external {
        for (uint256 i = 0; i < accounts.length; i++) {
            balances[accounts[i]] = amount;
        }
    }

    function batchTransfer(address from, address[] calldata tos, uint256 amount) external {
        for (uint256 i = 0; i < tos.length; i++) {
            balances[from] -= amount;
            balances[tos[i]] += amount;
        }
    }
}
''',
        contract_name="StoragePatterns",
        test_calls=[
            ("incrementCounter(uint256)", ["50"]),
            ("incrementCounter(uint256)", ["100"]),
            ("pushValues(uint256)", ["20"]),
            ("pushValues(uint256)", ["50"]),
        ],
    ),
    GasTestCase(
        test_id="math-intensive",
        description="Math-intensive operations",
        source_code='''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MathIntensive {
    uint256 public result;

    function fibonacci(uint256 n) external {
        if (n <= 1) {
            result = n;
            return;
        }
        uint256 a = 0;
        uint256 b = 1;
        for (uint256 i = 2; i <= n; i++) {
            uint256 temp = a + b;
            a = b;
            b = temp;
        }
        result = b;
    }

    function isPrime(uint256 n) external returns (bool) {
        if (n < 2) {
            result = 0;
            return false;
        }
        if (n == 2) {
            result = 1;
            return true;
        }
        if (n % 2 == 0) {
            result = 0;
            return false;
        }
        for (uint256 i = 3; i * i <= n; i += 2) {
            if (n % i == 0) {
                result = 0;
                return false;
            }
        }
        result = 1;
        return true;
    }

    function power(uint256 base, uint256 exp) external {
        result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result *= base;
        }
    }

    function gcd(uint256 a, uint256 b) external {
        while (b != 0) {
            uint256 temp = b;
            b = a % b;
            a = temp;
        }
        result = a;
    }
}
''',
        contract_name="MathIntensive",
        test_calls=[
            ("fibonacci(uint256)", ["20"]),
            ("fibonacci(uint256)", ["50"]),
            ("isPrime(uint256)", ["997"]),
            ("isPrime(uint256)", ["7919"]),
            ("power(uint256,uint256)", ["2", "10"]),
            ("gcd(uint256,uint256)", ["48", "18"]),
        ],
    ),
)


@dataclass
class CompilerSpec:
    """Specification for a compiler to compare."""
    spec_id: str
    name: str
    compiler_path: Path
    flags: Sequence[str]
    is_solx: bool = False


def compile_with_spec(
    spec: CompilerSpec,
    source_path: Path,
    output_dir: Path,
    contract_name: str,
    remappings: Dict[str, str] = None,
    import_paths: Sequence[str] = None,
    base_path: Optional[Path] = None,
    wrapper_source: Optional[str] = None,
) -> Tuple[Optional[str], int, str]:
    """Compile with a compiler spec and return (bytecode, code_size, error)."""
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Use wrapper source if provided (for abstract contracts)
    actual_source = source_path
    if wrapper_source:
        wrapper_path = output_dir / f"{contract_name}_wrapper.sol"
        wrapper_path.write_text(wrapper_source)
        actual_source = wrapper_path

    cmd = [str(spec.compiler_path)]
    cmd.extend(spec.flags)

    # Add remappings
    if remappings:
        for name, path in remappings.items():
            cmd.append(f"{name}={path}")

    # Add include paths
    if import_paths:
        for inc_path in import_paths:
            cmd.extend(["--include-path", inc_path])

    # Add base path if provided
    if base_path:
        cmd.extend(["--base-path", str(base_path)])

    # Add output options
    cmd.extend(["--bin", "--abi", "-o", str(output_dir), "--overwrite"])
    cmd.append(str(actual_source))

    result = run(cmd, timeout=120)

    if result.returncode != 0:
        return None, 0, result.stderr[:500]

    # Get bytecode
    bytecode = get_bytecode_from_output(output_dir, contract_name)
    if not bytecode:
        return None, 0, "No bytecode produced"

    code_size = len(bytecode) // 2  # hex to bytes
    return bytecode, code_size, ""


def run_code_size_comparison(
    contracts: Sequence[ContractConfig],
    specs: Sequence[CompilerSpec],
    base_path: Path,
    work_dir: Path,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """Run code size comparison across contracts and compiler specs."""
    results = []

    for contract in contracts:
        source_path = contract.source_path(base_path)
        if not source_path.exists():
            continue

        result_entry = {
            "contract_id": contract.contract_id,
            "label": contract.label,
            "project": contract.project,
            "sizes": {},
        }

        # Get base path for remappings
        repo_base = Path(contract.repo_path)
        if not repo_base.is_absolute():
            repo_base = base_path / contract.repo_path

        for spec in specs:
            output_dir = work_dir / contract.contract_id / spec.spec_id
            bytecode, code_size, error = compile_with_spec(
                spec, source_path, output_dir, contract.contract_name,
                contract.remappings, contract.import_paths, repo_base,
                contract.wrapper_source
            )

            if bytecode:
                result_entry["sizes"][spec.spec_id] = {
                    "size": code_size,
                    "status": "ok",
                }
                if verbose:
                    print(f"  {contract.contract_id} [{spec.spec_id}]: {code_size} bytes")
            else:
                result_entry["sizes"][spec.spec_id] = {
                    "size": 0,
                    "status": "failed",
                    "error": error[:200],
                }
                if verbose:
                    print(f"  {contract.contract_id} [{spec.spec_id}]: FAILED")

        results.append(result_entry)

    return results


def run_gas_comparison(
    test_cases: Sequence[GasTestCase],
    specs: Sequence[CompilerSpec],
    work_dir: Path,
    rpc_url: str,
    private_key: str,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """Run gas comparison for test cases."""
    results = []

    for test_case in test_cases:
        if verbose:
            print(f"\nRunning: {test_case.test_id} - {test_case.description}")

        result_entry = {
            "test_id": test_case.test_id,
            "description": test_case.description,
            "configs": {},
        }

        # Write source file
        source_path = work_dir / f"{test_case.test_id}.sol"
        source_path.write_text(test_case.source_code)

        for spec in specs:
            config_result = {
                "compile_status": "pending",
                "deploy_status": "pending",
                "gas_results": [],
                "total_gas": 0,
                "bytecode_size": 0,
            }
            result_entry["configs"][spec.spec_id] = config_result

            # Compile
            output_dir = work_dir / f"{test_case.test_id}_{spec.spec_id}"
            bytecode, code_size, error = compile_with_spec(
                spec, source_path, output_dir, test_case.contract_name
            )

            if not bytecode:
                config_result["compile_status"] = "failed"
                config_result["error"] = error
                if verbose:
                    print(f"  [{spec.spec_id}] Compile failed: {error[:100]}")
                continue

            config_result["compile_status"] = "ok"
            config_result["bytecode_size"] = code_size

            # Deploy with constructor args if any
            constructor_sig = None
            constructor_args = None
            if hasattr(test_case, 'constructor_args') and test_case.constructor_args:
                constructor_args = list(test_case.constructor_args)
                # Use explicit signature if provided
                if hasattr(test_case, 'constructor_sig') and test_case.constructor_sig:
                    constructor_sig = test_case.constructor_sig
                else:
                    # Infer constructor signature from args
                    # This is a simple heuristic - complex types need explicit signatures
                    arg_types = []
                    for arg in constructor_args:
                        if arg.startswith("0x") and len(arg) == 42:
                            arg_types.append("address")
                        elif arg.isdigit() or (arg.startswith("-") and arg[1:].isdigit()):
                            arg_types.append("uint256")
                        elif arg in ("true", "false"):
                            arg_types.append("bool")
                        else:
                            arg_types.append("string")
                    constructor_sig = f"constructor({','.join(arg_types)})"

            address = deploy_contract(
                bytecode, rpc_url, private_key,
                constructor_args, constructor_sig, verbose
            )
            if not address:
                config_result["deploy_status"] = "failed"
                if verbose:
                    print(f"  [{spec.spec_id}] Deploy failed")
                continue

            config_result["deploy_status"] = "ok"
            config_result["address"] = address

            # Run test calls
            total_gas = 0
            for sig, args in test_case.test_calls:
                gas = call_contract(address, sig, args, rpc_url, private_key, verbose)
                call_str = f"{sig}({', '.join(args)})" if args else sig
                if gas is not None:
                    config_result["gas_results"].append({
                        "call": call_str,
                        "gas": gas,
                    })
                    total_gas += gas
                else:
                    config_result["gas_results"].append({
                        "call": call_str,
                        "gas": None,
                        "error": "call failed",
                    })

            config_result["total_gas"] = total_gas
            if verbose:
                print(f"  [{spec.spec_id}] Total gas: {total_gas:,}")

        results.append(result_entry)

    return results


def print_code_size_comparison(
    results: List[Dict[str, Any]],
    specs: Sequence[CompilerSpec],
) -> None:
    """Print code size comparison table."""
    if not results:
        return

    print("\n" + _color("=" * 100, CYAN))
    print(_color("Code Size Comparison (bytes)", BOLD))
    print(_color("=" * 100, CYAN))

    # Header
    contract_width = max(len(r["label"]) for r in results) + 2
    spec_width = 15

    header = f"{'Contract':<{contract_width}}"
    for spec in specs:
        header += f" | {spec.name:>{spec_width}}"
    header += " | Improvement vs via-ir"
    print(header)
    print("-" * len(strip_ansi(header)))

    # Data rows
    for r in results:
        row = f"{r['label']:<{contract_width}}"
        sizes = []
        for spec in specs:
            size_data = r["sizes"].get(spec.spec_id, {})
            size = size_data.get("size", 0)
            sizes.append(size)
            status = size_data.get("status", "unknown")

            if status == "ok" and size > 0:
                cell = f"{size:>{spec_width},}"
            elif status == "failed":
                cell = _color(f"{'FAILED':>{spec_width}}", RED)
            else:
                cell = f"{'N/A':>{spec_width}}"
            row += f" | {cell}"

        # Calculate improvement vs baseline (first spec, typically via-ir)
        baseline = sizes[0] if sizes else 0
        if len(sizes) >= 2 and baseline > 0:
            # Show improvement for mlir-optimize (second spec)
            mlir_size = sizes[1]
            if mlir_size > 0:
                improvement = ((baseline - mlir_size) / baseline) * 100
                if improvement > 0:
                    imp_str = _color(f"+{improvement:.1f}%", GREEN)
                elif improvement < 0:
                    imp_str = _color(f"{improvement:.1f}%", RED)
                else:
                    imp_str = "0.0%"
                row += f" | {imp_str}"
            else:
                row += " | N/A"
        else:
            row += " | N/A"

        print(row)

    print("-" * len(strip_ansi(header)))

    # Summary
    print("\n" + _color("Summary:", BOLD))
    for spec in specs:
        total = sum(
            r["sizes"].get(spec.spec_id, {}).get("size", 0)
            for r in results
        )
        ok_count = sum(
            1 for r in results
            if r["sizes"].get(spec.spec_id, {}).get("status") == "ok"
        )
        print(f"  {spec.name}: {total:,} bytes total ({ok_count}/{len(results)} compiled)")


def print_gas_comparison(
    results: List[Dict[str, Any]],
    specs: Sequence[CompilerSpec],
) -> None:
    """Print gas comparison table."""
    if not results:
        return

    print("\n" + _color("=" * 100, CYAN))
    print(_color("Gas Usage Comparison", BOLD))
    print(_color("=" * 100, CYAN))

    # Header
    test_width = 25
    spec_width = 15

    header = f"{'Test Case':<{test_width}}"
    for spec in specs:
        header += f" | {spec.name:>{spec_width}}"
    header += " | Improvement"
    print(header)
    print("-" * len(strip_ansi(header)))

    # Data rows
    for r in results:
        row = f"{r['test_id']:<{test_width}}"

        gas_values = []
        for spec in specs:
            cfg_result = r["configs"].get(spec.spec_id, {})
            gas = cfg_result.get("total_gas", 0)
            gas_values.append(gas)

            if cfg_result.get("compile_status") != "ok":
                cell = _color(f"{'COMPILE_ERR':>{spec_width}}", RED)
            elif cfg_result.get("deploy_status") != "ok":
                cell = _color(f"{'DEPLOY_ERR':>{spec_width}}", RED)
            elif gas > 0:
                cell = f"{gas:>{spec_width},}"
            else:
                cell = f"{'N/A':>{spec_width}}"

            row += f" | {cell}"

        # Calculate improvement vs baseline (first spec)
        baseline = gas_values[0] if gas_values else 0
        if len(gas_values) >= 2 and baseline > 0:
            mlir_gas = gas_values[1]
            if mlir_gas > 0:
                improvement = ((baseline - mlir_gas) / baseline) * 100
                if improvement > 0:
                    imp_str = _color(f"+{improvement:.2f}%", GREEN)
                elif improvement < 0:
                    imp_str = _color(f"{improvement:.2f}%", RED)
                else:
                    imp_str = "0.00%"
                row += f" | {imp_str}"
            else:
                row += " | N/A"
        else:
            row += " | N/A"

        print(row)

    print("-" * len(strip_ansi(header)))

    # Summary
    print("\n" + _color("Summary:", BOLD))
    for spec in specs:
        total = sum(
            r["configs"].get(spec.spec_id, {}).get("total_gas", 0)
            for r in results
        )
        print(f"  {spec.name}: {total:,} total gas")


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

    # Comparison mode arguments
    parser.add_argument(
        "--solx",
        help="Path to solx binary for comparison",
    )
    parser.add_argument(
        "--codesize",
        action="store_true",
        help="Run code size comparison between via-ir, mlir-optimize, and solx",
    )
    parser.add_argument(
        "--gas",
        action="store_true",
        help="Run gas usage comparison (requires anvil running)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all benchmarks: compilation, code size, and gas comparison",
    )
    parser.add_argument(
        "--rpc-url",
        default=DEFAULT_RPC_URL,
        help=f"Anvil RPC URL (default: {DEFAULT_RPC_URL})",
    )
    parser.add_argument(
        "--private-key",
        default=DEFAULT_PRIVATE_KEY,
        help="Private key for transactions (default: anvil account 0)",
    )
    parser.add_argument(
        "--start-anvil",
        action="store_true",
        help="Start anvil automatically for gas comparison",
    )
    parser.add_argument(
        "--gas-tests",
        nargs="*",
        help="Subset of gas test IDs to run",
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

    # Handle --all flag
    if args.all:
        args.codesize = True
        args.gas = True

    # Find solx if comparison modes requested
    solx_path: Optional[Path] = None
    solx_version: Optional[str] = None
    if args.codesize or args.gas:
        solx_path, solx_version = detect_solx(args.solx)
        if solx_path:
            print(f"Using solx: {solx_path} (version: {solx_version})")
        else:
            print(_color("Warning: solx not found, will skip solx comparison", YELLOW))

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

    # Run comparison modes if requested
    comparison_results = {}
    anvil_proc = None

    try:
        # Build compiler specs for comparison
        if args.codesize or args.gas:
            specs: List[CompilerSpec] = [
                CompilerSpec(
                    spec_id="via-ir",
                    name="solc --via-ir",
                    compiler_path=solc_path,
                    flags=["--via-ir", "--optimize"],
                ),
                CompilerSpec(
                    spec_id="mlir-optimize",
                    name="solc --mlir",
                    compiler_path=solc_path,
                    flags=["--mlir-optimize"],
                ),
            ]
            if solx_path:
                specs.append(CompilerSpec(
                    spec_id="solx",
                    name="solx --via-ir",
                    compiler_path=solx_path,
                    flags=["--via-ir"],
                    is_solx=True,
                ))

        # Code size comparison
        if args.codesize:
            print("\n" + _color("Running Code Size Comparison...", BOLD))
            with tempfile.TemporaryDirectory() as work_dir:
                size_results = run_code_size_comparison(
                    all_contracts, specs, base_path, Path(work_dir), args.verbose
                )
                print_code_size_comparison(size_results, specs)
                comparison_results["code_size"] = size_results

        # Gas comparison
        if args.gas:
            # Check dependencies
            if not check_cast():
                print(_color("Error: 'cast' not found. Install foundry.", RED))
                return 1

            # Start anvil if requested
            if args.start_anvil:
                if not check_anvil():
                    print(_color("Error: 'anvil' not found. Install foundry.", RED))
                    return 1
                print("\nStarting anvil...")
                anvil_proc = start_anvil()

            print("\n" + _color("Running Gas Comparison...", BOLD))

            # Select gas test cases
            if args.gas_tests:
                test_map = {t.test_id: t for t in GAS_TEST_CASES}
                missing = [tid for tid in args.gas_tests if tid not in test_map]
                if missing:
                    print(_color(f"Unknown gas test IDs: {', '.join(missing)}", RED))
                    return 1
                gas_test_cases = [test_map[tid] for tid in args.gas_tests]
            else:
                gas_test_cases = list(GAS_TEST_CASES)

            with tempfile.TemporaryDirectory() as work_dir:
                gas_results = run_gas_comparison(
                    gas_test_cases, specs, Path(work_dir),
                    args.rpc_url, args.private_key, args.verbose
                )
                print_gas_comparison(gas_results, specs)
                comparison_results["gas"] = gas_results

        # Save comparison results
        if comparison_results:
            comparison_json = RESULT_ROOT / f"comparison_{timestamp}.json"
            comparison_json.write_text(json.dumps(comparison_results, indent=2, default=str))
            print(f"\nComparison results saved to {comparison_json}")

    finally:
        if anvil_proc:
            print("\nStopping anvil...")
            stop_anvil(anvil_proc)

    # Return non-zero if any failures
    failed_count = sum(1 for r in results if r["status"] == "failed")
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
