#!/usr/bin/env python3
"""
run_full_eval.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full evaluation pipeline — runs everything from scratch:
  1. SBOMit deep pipeline (witness --ebpf) per project
  2. Syft scan per project
  3. Trivy scan per project
  4. Upload attestations → generate SBOMs from server
  5. Extract ptrace compiled modules as ground truth
  6. Generate sbomit_full_evaluation.csv

Paths are auto-detected from the script location. Override via env vars:
  SBOMIT_DIR            — root of sbomit-generator-server (default: parent of this script)
  PROJECTS_BASE         — where build targets live on worker (default: $SBOMIT_DIR/projects)
  SERVER_URL            — server endpoint (default: http://10.10.20.2:5000)
  SERVER_TOKEN          — API token (default: sbomit-dev-token)
  SERVER_PROJECTS_BASE  — projects mount path inside server container (default: /projects)

Results go to $SBOMIT_DIR/eval_v2/
Previous results are NOT overwritten.
Safe to run with nohup — survives SSH disconnect.
"""

import os, json, csv, re, subprocess, time, base64, shutil
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────
# Auto-detect SBOMIT_DIR from script location (parent of evaluation/).
# Override with SBOMIT_DIR env var if needed.
SCRIPT_DIR  = Path(__file__).resolve().parent
SBOMIT_DIR  = Path(os.environ.get("SBOMIT_DIR", SCRIPT_DIR.parent))

# Projects base directory (where build targets live on the worker).
# Defaults to $SBOMIT_DIR/projects. Override with PROJECTS_BASE env var.
PROJECTS_BASE = Path(os.environ.get("PROJECTS_BASE", SBOMIT_DIR / "projects"))

# Server configuration (override with env vars for different deployments).
SERVER_URL = os.environ.get("SERVER_URL", "http://10.10.20.2:5000")
TOKEN      = os.environ.get("SERVER_TOKEN", "sbomit-dev-token")

# Server-side projects mount point (inside the docker container).
SERVER_PROJECTS_BASE = os.environ.get("SERVER_PROJECTS_BASE", "/projects")

# Derived paths
EVAL_DIR      = SBOMIT_DIR / "eval_v2"
LOGS_DIR      = EVAL_DIR / "logs"
RECORDS_DIR   = EVAL_DIR / "records"
BASELINES_DIR = EVAL_DIR / "baselines"
SBOMS_DIR     = EVAL_DIR / "sboms_v2"

for d in [LOGS_DIR, RECORDS_DIR, BASELINES_DIR, SBOMS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Project config: name -> (project_subdir, attest_dir, sbom_stem, skip_targets)
#   project_subdir : relative to PROJECTS_BASE (e.g. "gittuf" → $PROJECTS_BASE/gittuf)
#   attest_dir     : subdirectory name under attestations/ and attestations_v2/
#   sbom_stem      : filename stem for output SBOMs
#   skip_targets   : comma-separated list of step names to skip
#                    (passed to run_pipeline.py via --skip-targets)
# server_project_dir is computed automatically as SERVER_PROJECTS_BASE/project_subdir.
PROJECTS = {
    "gittuf":     ("gittuf",     "gittuf",     "gittuf",     "default,just-install,generate"),
    "python-tuf": ("python-tuf", "python-tuf", "python-tuf", ""),
    "go-tuf":     ("go-tuf",     "go-tuf",     "go-tuf",     ""),
    "in-toto":    ("in-toto",    "in-toto",    "in-toto",    "py38,py39,py310,py311,with-sslib-main"),
    "sbomit":     ("sbomit",     "sbomit",     "sbomit",     ""),
    "flux2":      ("flux2",      "flux2",      "flux2",      "all,setup-kind,cleanup-kind,e2e,test-with-kind,install-envtest"),
    "argo-cd":    ("argo-cd",    "argo-cd",    "argo-cd",    ""),
    "protobom":   ("protobom",   "protobom",   "protobom",   "help,conformance,conformance-test,fakes,buf-format,buf-lint"),
    "rust-tuf":   ("rust-tuf",   "rust-tuf",   "rust-tuf",   ""),
    "kyverno":    ("kyverno",    "kyverno",    "kyverno",    ""),
}

def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def run(cmd, cwd=None, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)

def curl(args, timeout=120):
    return subprocess.run(["curl", "-s"] + args, capture_output=True, text=True, timeout=timeout)

def fmt_time(s):
    if not s: return "—"
    return f"{s:.0f}s" if s < 60 else f"{s/60:.1f}m"

# ── Step 1: Run SBOMit pipeline ───────────────────────────────
def run_sbomit(project, project_subdir, attest_dir, skip):
    log(f"[{project}] Starting SBOMit deep pipeline...")
    attest_out = SBOMIT_DIR / "attestations_v2" / attest_dir
    attest_out.mkdir(parents=True, exist_ok=True)

    project_path = PROJECTS_BASE / project_subdir

    cmd = [
        "python3", str(SBOMIT_DIR / "run_pipeline.py"),
        "--project-dir", str(project_path),
        "--mode", "deep",
        "--prewarm",
    ]
    if skip:
        cmd += ["--skip-targets", skip]

    log_path = LOGS_DIR / f"{project}_sbomit.log"
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=str(SBOMIT_DIR),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = []
    for line in proc.stdout:
        line = line.rstrip()
        lines.append(line)
        if any(k in line for k in ["ATTESTING", "OK:", "FAIL:", "Done."]):
            log(f"  {line}")
    proc.wait()
    wall = round(time.time() - t0, 1)
    log_path.write_text("\n".join(lines))

    # Parse step timings
    steps = {}
    current = None
    for line in lines:
        m = re.match(r"^ATTESTING:\s+(\S+)", line)
        if m: current = m.group(1); steps[current] = {"status": "started", "phases": {}}
        m = re.match(r"^OK:\s+(\S+)", line)
        if m and m.group(1) in steps: steps[m.group(1)]["status"] = "ok"
        m = re.match(r"^FAIL:\s+(\S+)", line)
        if m: steps.setdefault(m.group(1), {})["status"] = "failed"
        m = re.match(r"^\s+(\S+)\s+start=\S+ \S+\s+duration=([0-9.]+)s", line)
        if m and current and current in steps:
            steps[current]["phases"][m.group(1)] = float(m.group(2))
            steps[current]["total_s"] = round(sum(steps[current]["phases"].values()), 2)

    # Copy attestations to v2 directory
    src = SBOMIT_DIR / "attestations" / attest_dir
    if src.exists():
        import shutil as _sh
        if attest_out.exists(): _sh.rmtree(attest_out)
        _sh.copytree(src, attest_out)
        log(f"  copied {len(list(attest_out.glob('*.json')))} attestation files to v2")
    log(f"[{project}] SBOMit done in {fmt_time(wall)} (exit={proc.returncode})")
    return {"wall_clock_s": wall, "exit_code": proc.returncode, "steps": steps,
            "attest_dir": str(attest_out), "log": str(log_path)}

# ── Step 2: Run Syft ──────────────────────────────────────────
def run_syft(project, project_subdir):
    log(f"[{project}] Running Syft...")
    out_dir = BASELINES_DIR / project
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "syft_spdx23.json"

    syft = shutil.which("syft") or "/usr/local/bin/syft"
    project_path = PROJECTS_BASE / project_subdir
    t0 = time.time()
    r = run([syft, str(project_path), "-o", "spdx-json"], timeout=300)
    wall = round(time.time() - t0, 1)

    pkg_count = 0
    if r.stdout.strip():
        try:
            data = json.loads(r.stdout)
            out_path.write_text(json.dumps(data, indent=2))
            pkg_count = len(data.get("packages", []))
        except: pass

    log(f"[{project}] Syft done: {pkg_count} packages in {fmt_time(wall)}")
    return {"wall_clock_s": wall, "packages": pkg_count, "output": str(out_path)}

# ── Step 3: Run Trivy ─────────────────────────────────────────
def run_trivy(project, project_subdir):
    log(f"[{project}] Running Trivy...")
    out_dir = BASELINES_DIR / project
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "trivy_spdx23.json"

    trivy = shutil.which("trivy") or "/usr/bin/trivy"
    project_path = PROJECTS_BASE / project_subdir
    t0 = time.time()
    r = run([trivy, "fs", "--format", "spdx-json", "--scanners", "license",
             "--output", str(out_path), str(project_path)], timeout=300)
    wall = round(time.time() - t0, 1)

    pkg_count = 0
    if out_path.exists():
        try:
            data = json.loads(out_path.read_text())
            pkg_count = len(data.get("packages", []))
        except: pass

    log(f"[{project}] Trivy done: {pkg_count} packages in {fmt_time(wall)}")
    return {"wall_clock_s": wall, "packages": pkg_count, "output": str(out_path)}

# ── Step 4: Upload attestations + generate SBOM ───────────────
def generate_sbom(project, project_subdir, attest_dir, sbom_stem):
    log(f"[{project}] Uploading attestations + generating SBOM...")
    attest_path = SBOMIT_DIR / "attestations_v2" / attest_dir

    # Server-side path (inside the docker container, via volume mount)
    server_project_dir = f"{SERVER_PROJECTS_BASE}/{project_subdir}"

    # Special case: rust-tuf uses local syft (server can't scan Rust)
    if project == "rust-tuf":
        log(f"[{project}] Using local syft for rust-tuf SBOM...")
        local_path = PROJECTS_BASE / project_subdir
        syft = shutil.which("syft") or "/usr/local/bin/syft"
        r = run([syft, str(local_path), "-o", "spdx-json"], timeout=300)
        if r.stdout.strip():
            data = json.loads(r.stdout)
            files = sorted(attest_path.glob("*.json")) if attest_path.exists() else []
            data["attestationSources"] = [f.name for f in files]
            data["catalogMode"] = f"syft ({local_path})"
            out = SBOMS_DIR / f"sbom-{sbom_stem}-rich.spdx.json"
            out.write_text(json.dumps(data, indent=2))
            pkg_count = len(data.get("packages", []))
            log(f"[{project}] SBOM ready: {pkg_count} packages (local syft)")
            return {"packages": pkg_count, "output": str(out)}

    # Clear server
    curl(["-X", "POST", f"{SERVER_URL}/attestations/clear",
          "-H", f"Authorization: Bearer {TOKEN}",
          "-H", "Content-Type: application/json",
          "-d", json.dumps({"project": project})])

    # Upload attestations
    files = sorted(attest_path.glob("*.json")) if attest_path.exists() else []
    log(f"[{project}] Uploading {len(files)} attestation files...")
    for f in files:
        curl(["-X", "POST", f"{SERVER_URL}/attestations",
              "-H", f"Authorization: Bearer {TOKEN}",
              "-H", "Content-Type: application/json",
              "-d", f"@{f}"], timeout=60)

    # Generate SBOM in all 3 formats
    pkg_count = 0
    for fmt, ext in [("spdx", "spdx.json"), ("cyclonedx", "cdx.json"), ("spdx22", "spdx22.json")]:
        out = SBOMS_DIR / f"sbom-{sbom_stem}-rich.{ext}"
        curl([f"{SERVER_URL}/sbom?format={fmt}&catalog=syft&project_dir={server_project_dir}",
              "-H", f"Authorization: Bearer {TOKEN}",
              "-o", str(out)], timeout=300)
        if fmt == "spdx" and out.exists():
            try:
                data = json.loads(out.read_text())
                pkg_count = len(data.get("packages", []))
            except: pass

    log(f"[{project}] SBOM ready: {pkg_count} packages")
    return {"packages": pkg_count, "output": str(SBOMS_DIR / f"sbom-{sbom_stem}-rich.spdx.json")}

# ── Step 5: Extract ptrace ground truth ───────────────────────
def extract_ptrace_modules(attest_dir):
    """Extract compiled packages from ptrace openedfiles for Go, Python and Rust."""
    modules = set()
    apath = SBOMIT_DIR / "attestations_v2" / attest_dir
    if not apath.exists(): return modules
    for f in sorted(apath.glob("*.json")):
        try:
            d = json.loads(f.read_text())
            decoded = json.loads(base64.b64decode(d.get('payload','')))
            for a in decoded.get('predicate',{}).get('attestations',[]):
                if 'command-run' not in a.get('type',''): continue
                for proc in a.get('attestation',{}).get('processes',[]):
                    for fpath in proc.get('openedfiles',{}).keys():
                        # Go: /go/pkg/mod/github.com/foo/bar@v1.2.3/...
                        m = re.match(r'.*/go/pkg/mod/([^@/]+(?:/[^@/]+)*)@([^/]+)', fpath)
                        if m and not m.group(1).startswith('cache/'):
                            modules.add(f"pkg:golang/{m.group(1)}@{m.group(2)}")
                            continue
                        # Python: .../site-packages/requests-2.28.0.dist-info/...
                        m = re.match(r'.*/site-packages/([A-Za-z0-9_.+-]+)-([0-9][^/]*)\.dist-info/', fpath)
                        if m:
                            name = m.group(1).lower().replace('-','_')
                            modules.add(f"pkg:pypi/{name}@{m.group(2)}")
                            continue
                        # Rust: .cargo/registry/cache/.../name-version.crate
                        m = re.match(r'.*/.cargo/registry/(?:cache|src)/[^/]+/(.+)-([0-9][0-9.]+[^/]*)\.crate$', fpath)
                        if m:
                            modules.add(f"pkg:cargo/{m.group(1)}@{m.group(2)}")
                            continue
        except: pass
    return modules

# ── Step 6: Extract PURLs from SBOM ──────────────────────────
def extract_purls(path):
    if not Path(path).exists(): return set()
    data = json.loads(Path(path).read_text())
    purls = set()
    for p in data.get('packages', []):
        for ref in p.get('externalRefs', []):
            if ref.get('referenceType') == 'purl':
                purls.add(ref.get('referenceLocator','').strip())
                break
    return purls

def dir_size_mb(path):
    p = Path(path)
    if not p.exists(): return 0.0
    return round(sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1024/1024, 2)

def file_size_mb(path):
    p = Path(path)
    return round(p.stat().st_size / 1024/1024, 2) if p.exists() else 0.0

def pct(a, b):
    return round(a/b*100, 1) if b else 0.0

# ── Main ──────────────────────────────────────────────────────
def main():
    log("="*60)
    log("SBOMit Full Evaluation v2 — starting")
    log(f"SBOMIT_DIR:    {SBOMIT_DIR}")
    log(f"PROJECTS_BASE: {PROJECTS_BASE}")
    log(f"SERVER_URL:    {SERVER_URL}")
    log(f"Output dir:    {EVAL_DIR}")
    log("="*60)

    all_records = {}

    for project, (project_subdir, attest_dir, sbom_stem, skip) in PROJECTS.items():
        log(f"\n{'='*60}")
        log(f"PROJECT: {project}")
        log(f"{'='*60}")

        record = {"project": project, "started_at": datetime.now(timezone.utc).isoformat()}

        # 1. SBOMit
        record["sbomit"] = run_sbomit(project, project_subdir, attest_dir, skip)

        # 2. Syft
        record["syft"] = run_syft(project, project_subdir)

        # 3. Trivy
        record["trivy"] = run_trivy(project, project_subdir)

        # 4. Generate SBOM
        record["sbom"] = generate_sbom(project, project_subdir, attest_dir, sbom_stem)

        # 5. ptrace ground truth
        traced = extract_ptrace_modules(attest_dir)
        record["ptrace_modules"] = len(traced)
        log(f"[{project}] ptrace compiled modules: {len(traced)}")

        # 6. Compute metrics
        syft_purls  = extract_purls(BASELINES_DIR / project / "syft_spdx23.json")
        trivy_purls = extract_purls(BASELINES_DIR / project / "trivy_spdx23.json")
        sbomit_purls = extract_purls(SBOMS_DIR / f"sbom-{sbom_stem}-rich.spdx.json")

        if traced:
            sy_hit  = syft_purls  & traced
            tr_hit  = trivy_purls & traced
            sy_fp   = syft_purls  - traced
            tr_fp   = trivy_purls - traced
            sy_miss = traced - syft_purls
            tr_miss = traced - trivy_purls
            record["ptrace_analysis"] = {
                "compiled_modules":           len(traced),
                "syft_captures_compiled":     len(sy_hit),
                "syft_captures_pct":          pct(len(sy_hit), len(traced)),
                "syft_misses_compiled":       len(sy_miss),
                "syft_false_positives":       len(sy_fp),
                "syft_false_positive_pct":    pct(len(sy_fp), len(syft_purls)),
                "trivy_captures_compiled":    len(tr_hit),
                "trivy_captures_pct":         pct(len(tr_hit), len(traced)),
                "trivy_misses_compiled":      len(tr_miss),
                "trivy_false_positives":      len(tr_fp),
                "trivy_false_positive_pct":   pct(len(tr_fp), len(trivy_purls)),
            }

        record["package_counts"] = {
            "sbomit":  len(sbomit_purls),
            "syft":    len(syft_purls),
            "trivy":   len(trivy_purls),
        }

        record["sizes"] = {
            "attestation_mb":  dir_size_mb(SBOMIT_DIR / "attestations_v2" / attest_dir),
            "sbomit_sbom_mb":  file_size_mb(SBOMS_DIR / f"sbom-{sbom_stem}-rich.spdx.json"),
            "syft_sbom_mb":    file_size_mb(BASELINES_DIR / project / "syft_spdx23.json"),
            "trivy_sbom_mb":   file_size_mb(BASELINES_DIR / project / "trivy_spdx23.json"),
        }

        record["completed_at"] = datetime.now(timezone.utc).isoformat()
        all_records[project] = record

        # Save per-project record
        rec_path = RECORDS_DIR / f"{project}.json"
        rec_path.write_text(json.dumps(record, indent=2))
        log(f"[{project}] Record saved: {rec_path}")

    # ── Generate CSV ──────────────────────────────────────────
    log("\nGenerating sbomit_full_evaluation.csv...")
    rows = []
    for project, rec in all_records.items():
        pa = rec.get("ptrace_analysis", {})
        pc = rec.get("package_counts", {})
        sz = rec.get("sizes", {})
        sb = rec.get("sbomit", {})
        sy = rec.get("syft", {})
        tr = rec.get("trivy", {})
        steps = sb.get("steps", {})
        step_times = {k: v.get("total_s", 0) for k, v in steps.items()
                      if v.get("status") != "skipped" and v.get("total_s", 0) > 0}

        row = {
            "project":                     project,
            # Package counts
            "sbomit_packages":             pc.get("sbomit", 0),
            "syft_packages":               pc.get("syft", 0),
            "trivy_packages":              pc.get("trivy", 0),
            # ptrace ground truth
            "ptrace_compiled_modules":     pa.get("compiled_modules", "N/A"),
            # Syft vs ptrace
            "syft_captures_compiled_pct":  pa.get("syft_captures_pct", "N/A"),
            "syft_misses_compiled":        pa.get("syft_misses_compiled", "N/A"),
            "syft_false_positives":        pa.get("syft_false_positives", "N/A"),
            "syft_false_positive_pct":     pa.get("syft_false_positive_pct", "N/A"),
            # Trivy vs ptrace
            "trivy_captures_compiled_pct": pa.get("trivy_captures_pct", "N/A"),
            "trivy_misses_compiled":       pa.get("trivy_misses_compiled", "N/A"),
            "trivy_false_positives":       pa.get("trivy_false_positives", "N/A"),
            "trivy_false_positive_pct":    pa.get("trivy_false_positive_pct", "N/A"),
            # Timing
            "sbomit_time_s":               sb.get("wall_clock_s", 0),
            "sbomit_time_min":             round(sb.get("wall_clock_s", 0)/60, 2),
            "syft_time_s":                 sy.get("wall_clock_s", 0),
            "trivy_time_s":                tr.get("wall_clock_s", 0),
            "sbomit_vs_syft_slowdown_x":   round(sb.get("wall_clock_s",0)/sy.get("wall_clock_s",1), 1),
            "sbomit_vs_trivy_slowdown_x":  round(sb.get("wall_clock_s",0)/tr.get("wall_clock_s",1), 1),
            # Step breakdown
            "step_fmt_s":      step_times.get("fmt",     step_times.get("go-fmt",   0)),
            "step_build_s":    step_times.get("build",   step_times.get("go-build", 0)),
            "step_test_s":     step_times.get("test",    step_times.get("go-test",  0)),
            "step_install_s":  step_times.get("install", 0),
            # Sizes
            "attestation_mb":  sz.get("attestation_mb", 0),
            "sbomit_sbom_mb":  sz.get("sbomit_sbom_mb", 0),
            "syft_sbom_mb":    sz.get("syft_sbom_mb", 0),
            "trivy_sbom_mb":   sz.get("trivy_sbom_mb", 0),
        }
        rows.append(row)

    csv_path = EVAL_DIR / "sbomit_full_evaluation.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    log(f"CSV saved: {csv_path}")
    log("\nALL DONE!")
    log(f"Results in: {EVAL_DIR}")

if __name__ == "__main__":
    main()