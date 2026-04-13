#!/usr/bin/env python3
"""
disambiguate.py — Supply chain disambiguation using sbomit.

Compares two sbomit runs to identify:
  1. Packages actually compiled (sbomit alone, from --trace syscall data)
  2. Packages syft adds from filesystem scan (sbomit --catalog syft)
  3. The delta = packages syft reports but were never compiled

Requires:
  - A Deep run attestation: ~/SBOMIT/attestations/<project>/build.json
  - sbomit binary: ~/SBOMIT/sbomit
  - syft binary: ~/bin/syft (or in PATH)

Usage:
    python3 disambiguate.py --project gittuf
    python3 disambiguate.py --project gittuf --format json --output report.json
    python3 disambiguate.py --project gittuf --format csv  --output report.csv
    python3 disambiguate.py --project gittuf --attestation /path/to/build.json
"""

import json
import re
import argparse
import subprocess
import sys
import os
import csv
import collections
from datetime import datetime
from pathlib import Path

SBOMIT_DIR = Path(__file__).parent.resolve()
SBOMIT_BIN = SBOMIT_DIR / "sbomit"
SYFT_BIN   = Path.home() / "bin" / "syft"

PROJECTS = {
    "gittuf":  Path.cwd().parent / "benchmark-projects/gittuf",
    "tuf":     Path.cwd().parent / "benchmark-projects/tuf",
    "intoto":  Path.cwd().parent / "benchmark-projects/intoto",
    "sbomit":  Path.cwd().parent / "benchmark-projects/sbomit",
    "kyverno": Path.cwd().parent / "benchmark-projects/kyverno",
    "argocd":  Path.cwd().parent / "benchmark-projects/argo-cd",
    "flux2":   Path.cwd().parent / "benchmark-projects/flux2",
    "protobom": Path.cwd().parent / "benchmark-projects/protobom",
}


def run_sbomit(attestation_path, project_dir=None):
    """Run sbomit generate and return (set of purls, full SBOM dict)."""
    if not SBOMIT_BIN.exists():
        print(f"ERROR: sbomit binary not found at {SBOMIT_BIN}")
        print("       Build: cd ~/projects/sbomit && go build -o sbomit . && cp sbomit ~/SBOMIT/")
        sys.exit(1)

    cmd = [str(SBOMIT_BIN), "generate", str(attestation_path), "--format", "spdx23"]
    env = os.environ.copy()

    if project_dir:
        if SYFT_BIN.exists():
            env["PATH"] = str(SYFT_BIN.parent) + ":" + env.get("PATH", "")
        cmd += ["--catalog", "syft", "--project-dir", str(project_dir)]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    try:
        sbom = json.loads(result.stdout)
    except json.JSONDecodeError:
        return set(), {}

    purls = {
        ref["referenceLocator"]
        for pkg in sbom.get("packages", [])
        for ref in pkg.get("externalRefs", [])
        if ref.get("referenceType") == "purl"
    }
    return purls, sbom


def get_attestor_timing(attestation_path):
    """Parse attestation file and return timing per attestor."""
    import base64
    try:
        with open(attestation_path) as f:
            data = json.load(f)
        payload_raw = data.get("payload", "")
        if isinstance(payload_raw, str):
            try:
                payload = json.loads(base64.b64decode(payload_raw + "=="))
            except Exception:
                payload = json.loads(base64.b64decode(payload_raw))
        else:
            payload = payload_raw

        timing = {}
        for a in payload.get("predicate", {}).get("attestations", []):
            short = a.get("type", "").split("/")[-2] if "/" in a.get("type", "") else "unknown"
            start, end = a.get("starttime", ""), a.get("endtime", "")
            duration = None
            if start and end:
                try:
                    s = re.sub(r'(\.\d{6})\d+Z$', r'\1+00:00', start)
                    e = re.sub(r'(\.\d{6})\d+Z$', r'\1+00:00', end)
                    from datetime import datetime as dt
                    duration = round((dt.fromisoformat(e) - dt.fromisoformat(s)).total_seconds(), 3)
                except Exception:
                    pass
            timing[short] = {
                "starttime":  start[:19].replace("T", " ") if start else "n/a",
                "duration_s": duration,
            }
        return timing
    except Exception:
        return {}


def find_multi_version(purls):
    """Find packages appearing at multiple versions."""
    versions = collections.defaultdict(set)
    for purl in purls:
        m = re.match(r'pkg:[^/]+/(.+)@([^\s]+)', purl)
        if m:
            versions[m.group(1)].add(m.group(2))
    return {k: sorted(v) for k, v in versions.items() if len(v) > 1}


def sbom_quality(sbom):
    pkgs = sbom.get("packages", [])
    return {
        "total":             len(pkgs),
        "with_checksum":     sum(1 for p in pkgs if p.get("checksums")),
        "with_purpose":      sum(1 for p in pkgs if p.get("primaryPackagePurpose")
                                 and p["primaryPackagePurpose"] not in ("UNSET", "")),
        "with_relationships": len(sbom.get("relationships", [])),
    }


def run_analysis(project, attestation_file=None):
    if attestation_file is None:
        attestation_file = SBOMIT_DIR / "attestations" / project / "build.json"
    attestation_file = Path(attestation_file)
    project_dir = PROJECTS.get(project)

    if not attestation_file.exists():
        print(f"ERROR: Attestation not found: {attestation_file}")
        print(f"       Run a Deep run for {project} first.")
        sys.exit(1)

    print(f"Project:     {project}")
    print(f"Attestation: {attestation_file}")
    print(f"Project dir: {project_dir}")
    print()

    print("Running sbomit (attestation only — --trace compiled packages)...")
    sbomit_pkgs, sbomit_sbom = run_sbomit(attestation_file)

    if project_dir and project_dir.exists():
        print("Running sbomit + syft (attestation + filesystem scan)...")
        combined_pkgs, combined_sbom = run_sbomit(attestation_file, project_dir)
    else:
        combined_pkgs, combined_sbom = set(), {}
        print("No project dir — skipping syft catalog")

    print()

    sbomit_only = sbomit_pkgs - combined_pkgs
    syft_only   = combined_pkgs - sbomit_pkgs
    both        = sbomit_pkgs & combined_pkgs

    return {
        "project":          project,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "attestation_file": str(attestation_file),
        "project_dir":      str(project_dir) if project_dir else None,
        "sbomit_count":     len(sbomit_pkgs),
        "combined_count":   len(combined_pkgs),
        "both_count":       len(both),
        "sbomit_only":      sorted(sbomit_only),
        "syft_only":        sorted(syft_only),
        "both":             sorted(both),
        "multi_version":    find_multi_version(sbomit_pkgs),
        "attestor_timing":  get_attestor_timing(attestation_file),
        "sbomit_quality":   sbom_quality(sbomit_sbom),
        "combined_quality": sbom_quality(combined_sbom),
    }


def print_text(r):
    print("=" * 65)
    print(f"DISAMBIGUATION REPORT \u2014 {r['project']}")
    print(f"Generated: {r['timestamp']}")
    print("=" * 65)
    print()

    if r["attestor_timing"]:
        print("\u25b6  ATTESTOR TIMING")
        for atype, info in r["attestor_timing"].items():
            dur = f"{info['duration_s']}s" if info['duration_s'] is not None else "n/a"
            print(f"   {atype:<15} start={info['starttime']}  duration={dur}")
        print()

    print("\u25b6  PACKAGE ANALYSIS")
    print(f"   sbomit alone  (--trace compiled):  {r['sbomit_count']}")
    print(f"   sbomit + syft (+ filesystem scan): {r['combined_count']}")
    print(f"   In both:                           {r['both_count']}")
    print()

    sq, cq = r["sbomit_quality"], r["combined_quality"]
    print("\u25b6  SBOM QUALITY")
    print(f"   {'Metric':<28} {'sbomit':>8}  {'sbomit+syft':>12}")
    print(f"   {'Total packages':<28} {sq['total']:>8}  {cq['total']:>12}")
    print(f"   {'With SHA256 checksum':<28} {sq['with_checksum']:>8}  {cq['with_checksum']:>12}")
    print(f"   {'With primaryPackagePurpose':<28} {sq['with_purpose']:>8}  {cq['with_purpose']:>12}")
    print(f"   {'Relationships':<28} {sq['with_relationships']:>8}  {cq['with_relationships']:>12}")
    print()

    if r["multi_version"]:
        print(f"\u26a0\ufe0f  MULTI-VERSION CONFLICTS ({len(r['multi_version'])}) \u2014 disambiguation needed:")
        for mod, vers in sorted(r["multi_version"].items()):
            print(f"   {mod}")
            for v in vers:
                print(f"     \u2192 {v}")
    else:
        print("\u2705 No multi-version conflicts \u2014 Go MVS resolved cleanly")
    print()

    if r["sbomit_only"]:
        print(f"\u2728  COMPILED BUT SYFT MISSED ({len(r['sbomit_only'])}):")
        for p in r["sbomit_only"][:15]:
            print(f"   + {p}")
        if len(r["sbomit_only"]) > 15:
            print(f"   ... ({len(r['sbomit_only'])} total)")
    else:
        print("\u2705 Syft found all compiled packages \u2014 no gaps")
    print()

    if r["syft_only"]:
        print(f"\u26a0\ufe0f  SYFT REPORTS BUT NEVER COMPILED ({len(r['syft_only'])}) \u2014 potential CVE false positives:")
        for p in r["syft_only"][:15]:
            print(f"   - {p}")
        if len(r["syft_only"]) > 15:
            print(f"   ... ({len(r['syft_only'])} total)")
    else:
        print("\u2705 No over-reported packages")
    print()
    print("=" * 65)


def print_csv(r, output_path):
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["purl", "in_compiled", "in_syft", "status"])
        all_pkgs = set(r["both"]) | set(r["sbomit_only"]) | set(r["syft_only"])
        for purl in sorted(all_pkgs):
            in_compiled = purl in set(r["both"]) or purl in set(r["sbomit_only"])
            in_syft     = purl in set(r["both"]) or purl in set(r["syft_only"])
            if in_compiled and in_syft:
                status = "correct"
            elif in_compiled:
                status = "compiled_syft_missed"
            else:
                status = "syft_only_never_compiled"
            writer.writerow([purl, in_compiled, in_syft, status])
    print(f"CSV saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Disambiguate compiled packages using sbomit generate"
    )
    parser.add_argument("--project",     required=True)
    parser.add_argument("--attestation", default=None)
    parser.add_argument("--format",      default="text", choices=["text", "json", "csv"])
    parser.add_argument("--output",      default=None)
    args = parser.parse_args()

    result = run_analysis(args.project, args.attestation)

    if args.format == "text":
        print_text(result)
        if args.output:
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_text(result)
            Path(args.output).write_text(buf.getvalue())
            print(f"Report saved to: {args.output}")
    elif args.format == "json":
        out = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(out)
            print(f"JSON saved to: {args.output}")
        else:
            print(out)
    elif args.format == "csv":
        print_csv(result, args.output or f"disambiguate-{args.project}.csv")


if __name__ == "__main__":
    main()
