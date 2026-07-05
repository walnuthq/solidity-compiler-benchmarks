#!/usr/bin/env python3
"""Compile-sweep the corpus with solar's codegen and hunt ICEs and regressions.

This automates the checks used while hardening solar against this corpus:

  1. Compile every tracked `.sol` standalone with `-Zcodegen --emit bin-runtime`
     and classify each file:
       OK      compiled cleanly
       DIAG    clean compiler diagnostic (unimplemented feature, type error, ...)
       DEP     missing import/dependency (standalone artifact; solc fails too)
       ICE     compiler panic ("unexpectedly panicked") -- always a bug
       TIMEOUT compilation exceeded the per-file timeout
  2. Enforce expectations:
       - must-pass projects (everything under aave-v3-core/contracts/protocol)
         must be all-OK;
       - contracts known to sit near the EIP-170 limit (nitro
         OneStepProofEntry) must stay under 24576 bytes of runtime code, so an
         inlining/codegen size regression is caught before the bench's
         DEPLOY_ERR does.
  3. Optionally cross-check every solar failure against solc (--cross-check,
     needs --solc): failures that also fail in solc are corpus artifacts, not
     solar bugs.
  4. Optionally chain the authoritative runtime bench (--bench, needs --solc)
     and the solar UI test suite (--ui).

Exit code is non-zero when any ICE appears, a must-pass file stops compiling,
a critical size check fails, or a chained bench/UI run fails.

Typical use after changing solar:

    cargo build -p solar-compiler --bin solar        # in ../solar
    ./solar_corpus_check.py                          # fast: sweep + size checks
    ./solar_corpus_check.py --cross-check --bench    # full gate (needs --solc)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent
EIP170_LIMIT = 24576
DEFAULT_SOLAR = REPO.parent / "solar" / "target" / "debug" / "solar"
DEFAULT_SOLC = Path.home() / ".solc-select" / "artifacts" / "solc-0.8.30" / "solc-0.8.30"

# (name, project_root, include_dirs (relative to root), scan_dirs (relative), must_pass)
PROJECTS = [
    ("aave-protocol", "aave-v3-core", ["contracts"], ["contracts/protocol"], True),
    ("aave-flashloan", "aave-v3-core", ["contracts"], ["contracts/flashloan"], False),
    ("aave-misc", "aave-v3-core", ["contracts"], ["contracts/misc"], False),
    ("nitro-osp", "nitro-contracts", ["src", "node_modules"], ["src/osp"], True),
    ("nitro-state", "nitro-contracts", ["src", "node_modules"], ["src/state"], False),
    ("nitro-mocks", "nitro-contracts", ["src", "node_modules"], ["src/mocks"], False),
]

# Contracts that sit near the EIP-170 limit. If one of these stops fitting,
# the bench fails with DEPLOY_ERR -- catch it here with a clear message.
# (project name, defining file basename, contract name)
CRITICAL_SIZES = [
    ("nitro-osp", "OneStepProofEntry.sol", "OneStepProofEntry"),
]

# Library-linked deployability gates: compile with --libraries (dummy
# addresses) and require the contract to fit EIP-170, guarding the
# delegatecall-linking size win (Pool: 92 KB inlined -> ~19 KB linked).
# (label, project_root, includes, source, contract, libraries-spec)
AAVE_LOGIC_LIBS = ",".join(
    f"{name}=0x10000000000000000000000000000000000000{i:02x}"
    for i, name in enumerate(
        ["SupplyLogic", "BorrowLogic", "LiquidationLogic", "EModeLogic",
         "BridgeLogic", "FlashLoanLogic", "PoolLogic", "ConfiguratorLogic"], 1)
)
LINKED_SIZE_CHECKS = [
    ("Pool (linked)", "aave-v3-core", ["contracts"],
     "contracts/protocol/pool/Pool.sol", "Pool", AAVE_LOGIC_LIBS),
    ("PoolConfigurator (linked)", "aave-v3-core", ["contracts"],
     "contracts/protocol/pool/PoolConfigurator.sol", "PoolConfigurator", AAVE_LOGIC_LIBS),
]

ICE_RE = re.compile(r"panicked at ([^\s,]+\.rs:\d+)")
DEP_RE = re.compile(r"^error: file .+ not found", re.M)
ERR_RE = re.compile(r"^(error(\[[^\]]+\])?: (?!aborting).+)$", re.M)


def compile_one(solar, root, includes, path, timeout, opt=None):
    cmd = [str(solar), "-Zcodegen", "--emit", "bin-runtime", "--color", "never",
           "--base-path", str(root)]
    if opt:
        cmd += ["-O", opt]
    for inc in includes:
        inc_path = root / inc
        if inc_path.is_dir():
            cmd += ["-I", str(inc_path)]
    cmd.append(str(path))
    env = {**os.environ, "RUST_BACKTRACE": "0"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"file": path, "status": "TIMEOUT", "detail": f"exceeded {timeout}s"}

    stderr = proc.stderr or ""
    if "panicked" in stderr:
        site = ICE_RE.search(stderr)
        return {"file": path, "status": "ICE",
                "detail": site.group(1) if site else "panic (site not parsed)"}
    if proc.returncode != 0 or ERR_RE.search(stderr):
        if DEP_RE.search(stderr):
            return {"file": path, "status": "DEP", "detail": DEP_RE.search(stderr).group(0)}
        first = ERR_RE.search(stderr)
        return {"file": path, "status": "DIAG",
                "detail": first.group(1) if first else f"exit {proc.returncode}"}

    sizes = {}
    try:
        out = json.loads(proc.stdout or "{}")
        for name, contract in out.get("contracts", {}).items():
            runtime = contract.get("bin-runtime") or ""
            sizes[name] = len(runtime) // 2
    except json.JSONDecodeError:
        pass
    return {"file": path, "status": "OK", "detail": "", "sizes": sizes}


def linked_size_check(solar, label, root, includes, source, contract, libs, timeout):
    cmd = [str(solar), "-Zcodegen", "--libraries", libs, "--emit", "bin-runtime",
           "--color", "never", "--base-path", str(root)]
    for inc in includes:
        inc_path = root / inc
        if inc_path.is_dir():
            cmd += ["-I", str(inc_path)]
    cmd.append(str(root / source))
    env = {**os.environ, "RUST_BACKTRACE": "0"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return (label, None, "timeout")
    if "panicked" in (proc.stderr or ""):
        return (label, None, "ICE")
    try:
        out = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return (label, None, "no output")
    for name, c in out.get("contracts", {}).items():
        if name.endswith(f":{contract}"):
            return (label, len((c.get("bin-runtime") or "")) // 2, None)
    return (label, None, "contract missing")


def solc_also_fails(solc, root, includes, path, timeout):
    cmd = [str(solc), "--bin", "--base-path", str(root)]
    for inc in includes:
        inc_path = root / inc
        if inc_path.is_dir():
            cmd += ["--include-path", str(inc_path)]
    cmd.append(str(path))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode != 0


def collect_files(root, scan_dirs):
    files = []
    for scan in scan_dirs:
        base = root / scan
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.sol")):
            if "node_modules" in path.parts or "lib" in path.parts:
                continue
            files.append(path)
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--solar", default=str(DEFAULT_SOLAR), help="solar binary")
    ap.add_argument("--solc", default=str(DEFAULT_SOLC),
                    help="solc binary (for --cross-check / --bench)")
    ap.add_argument("--project", action="append",
                    help="only these projects (repeatable); see --list")
    ap.add_argument("--list", action="store_true", help="list projects and exit")
    ap.add_argument("--jobs", type=int, default=max(2, (os.cpu_count() or 4) // 2))
    ap.add_argument("--timeout", type=int, default=60, help="per-file compile timeout (s)")
    ap.add_argument("--opt", choices=["none", "gas", "size"], default=None,
                    help="pass -O <mode> to solar (default: solar's default, gas)")
    ap.add_argument("--cross-check", action="store_true",
                    help="re-run solar failures through solc; both-fail = corpus artifact")
    ap.add_argument("--bench", action="store_true",
                    help="also run ./solar_bench.py --suite repo (the runtime gate)")
    ap.add_argument("--ui", action="store_true",
                    help="also run solar's UI test suite (cargo test in ../solar)")
    ap.add_argument("--verbose", action="store_true", help="print every file's status")
    args = ap.parse_args()

    if args.list:
        for name, root, _, scans, must in PROJECTS:
            tag = "must-pass" if must else "informational"
            print(f"{name:16} {root}/{{{','.join(scans)}}}  [{tag}]")
        return 0

    solar = Path(args.solar)
    if not solar.is_file():
        sys.exit(f"solar binary not found: {solar} (build with: cargo build -p solar-compiler --bin solar)")

    selected = [p for p in PROJECTS if not args.project or p[0] in args.project]
    if not selected:
        sys.exit(f"no matching projects; use --list. got: {args.project}")

    failures_fatal = []
    all_ices = []
    size_warnings = {}  # (project, contract basename) -> max size seen
    project_results = {}
    t0 = time.time()

    for name, root_rel, includes, scan_dirs, must_pass in selected:
        root = REPO / root_rel
        files = collect_files(root, scan_dirs)
        if not files:
            print(f"[{name}] no files found under {root_rel}/{scan_dirs} -- skipped")
            continue

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(
                lambda f: compile_one(solar, root, includes, f, args.timeout, args.opt), files))

        counts = {"OK": 0, "DIAG": 0, "DEP": 0, "ICE": 0, "TIMEOUT": 0}
        for res in results:
            counts[res["status"]] += 1
            rel = res["file"].relative_to(REPO)
            if res["status"] == "ICE":
                all_ices.append((name, rel, res["detail"]))
            if res["status"] == "OK":
                for contract, size in res.get("sizes", {}).items():
                    if size > EIP170_LIMIT:
                        key = (name, contract.split("/")[-1])
                        size_warnings[key] = max(size_warnings.get(key, 0), size)
            if args.verbose or res["status"] in ("ICE", "TIMEOUT"):
                if res["status"] != "OK":
                    print(f"  {res['status']:7} {rel}  {res['detail']}")

        # Cross-check non-OK files against solc: both-fail = corpus artifact.
        if args.cross_check and Path(args.solc).is_file():
            for res in results:
                if res["status"] in ("DIAG", "DEP"):
                    if solc_also_fails(args.solc, root, includes, res["file"], args.timeout):
                        res["both_fail"] = True

        solar_only = [r for r in results
                      if r["status"] in ("DIAG", "DEP") and not r.get("both_fail")]
        project_results[name] = results

        line = (f"[{name}] {counts['OK']}/{len(files)} OK"
                f"  diag={counts['DIAG']} dep={counts['DEP']}"
                f" ice={counts['ICE']} timeout={counts['TIMEOUT']}")
        if args.cross_check:
            line += f"  solar-only-failures={len(solar_only)}"
        print(line)

        if must_pass and counts["OK"] != len(files):
            for res in results:
                if res["status"] != "OK":
                    failures_fatal.append(
                        (name, res["file"].relative_to(REPO), res["status"], res["detail"]))

        if not args.verbose:
            for res in results:
                if res["status"] in ("DIAG", "DEP") and not res.get("both_fail"):
                    print(f"    {res['status']:4} {res['file'].relative_to(REPO)}"
                          f"  {res['detail']}")

    # Critical EIP-170 size checks.
    size_failures = []
    for proj, basename, contract in CRITICAL_SIZES:
        for res in project_results.get(proj, []):
            if res["file"].name == basename and res["status"] == "OK":
                for cname, size in res.get("sizes", {}).items():
                    if cname.endswith(f":{contract}"):
                        ok = size <= EIP170_LIMIT
                        print(f"[size] {contract}: {size} B "
                              f"({'OK, ' + str(EIP170_LIMIT - size) + ' B spare' if ok else 'OVER EIP-170 LIMIT by ' + str(size - EIP170_LIMIT) + ' B'})")
                        if not ok:
                            size_failures.append((contract, size))

    for (name, contract), size in sorted(size_warnings.items(), key=lambda kv: -kv[1]):
        print(f"[size] warning: {contract} = {size} B (> {EIP170_LIMIT}, undeployable) [{name}]")

    # Library-linked deployability gates.
    for label, root_rel, includes, source, contract, libs in LINKED_SIZE_CHECKS:
        root = REPO / root_rel
        if not (root / source).is_file():
            continue
        label_out, size, err = linked_size_check(
            solar, label, root, includes, source, contract, libs, args.timeout)
        if err is not None:
            print(f"[size] {label_out}: FAILED ({err})")
            size_failures.append((label_out, 0))
        elif size <= EIP170_LIMIT:
            print(f"[size] {label_out}: {size} B (OK, {EIP170_LIMIT - size} B spare)")
        else:
            print(f"[size] {label_out}: {size} B (OVER EIP-170 LIMIT by {size - EIP170_LIMIT} B)")
            size_failures.append((label_out, size))

    bench_rc = ui_rc = 0
    if args.bench:
        if not Path(args.solc).is_file():
            sys.exit(f"--bench needs solc; not found: {args.solc}")
        print("\n=== solar_bench.py --suite repo (runtime differential) ===")
        bench_rc = subprocess.run(
            [str(REPO / "solar_bench.py"), "--solc", args.solc, "--solar", str(solar),
             "--suite", "repo", "--gas", "--gas-profile", "smoke", "--start-anvil"],
            cwd=REPO).returncode

    if args.ui:
        solar_repo = solar.resolve().parents[2] if solar.name == "solar" else REPO.parent / "solar"
        print(f"\n=== solar UI tests ({solar_repo}) ===")
        ui_rc = subprocess.run(
            ["cargo", "test", "-q", "-p", "solar-compiler", "--test", "tests"],
            cwd=solar_repo).returncode

    print(f"\n=== verdict ({time.time() - t0:.0f}s) ===")
    ok = True
    if all_ices:
        ok = False
        print(f"FAIL: {len(all_ices)} ICE(s):")
        for name, rel, detail in all_ices:
            print(f"  [{name}] {rel}  {detail}")
    if failures_fatal:
        ok = False
        print(f"FAIL: must-pass files not compiling:")
        for name, rel, status, detail in failures_fatal:
            print(f"  [{name}] {status} {rel}  {detail}")
    if size_failures:
        ok = False
        for contract, size in size_failures:
            print(f"FAIL: {contract} = {size} B exceeds EIP-170 ({EIP170_LIMIT} B) -- bench will DEPLOY_ERR")
    if args.bench and bench_rc != 0:
        ok = False
        print(f"FAIL: bench exited {bench_rc}")
    if args.ui and ui_rc != 0:
        ok = False
        print(f"FAIL: UI tests exited {ui_rc}")
    if ok:
        print("PASS: no ICEs, must-pass projects compile, critical sizes fit"
              + (", bench OK" if args.bench else "")
              + (", UI OK" if args.ui else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
