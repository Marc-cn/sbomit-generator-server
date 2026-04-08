#!/usr/bin/env python3
"""
disambiguate.py — Cross-reference witness --trace attestation with SBOM packages.
                  Optionally compare sbomit SBOM vs syft SBOM (Point 3).

Usage:
    # Witness trace vs syft SBOM (original disambiguation)
    python3 disambiguate.py --project gittuf

    # sbomit SBOM vs syft SBOM delta (Abhishek's suggestion)
    python3 disambiguate.py --project gittuf --compare-catalogs

    # Both analyses together
    python3 disambiguate.py --project gittuf --compare-catalogs --full

    # Output formats
    python3 disambiguate.py --project gittuf --format json --output report.json
    python3 disambiguate.py --project gittuf --format csv  --output report.csv

Requires:
    - ~/SBOMIT/attestations/<project>/build.json  (from a Deep run)
    - ~/SBOMIT/sboms/sbom-<project>-rich.spdx.json
    - ~/SBOMIT/sbomit binary (only for --compare-catalogs)
"""

import json
import re
import base64
import argparse
import sys
import os
import csv
import subprocess
import tempfile
import collections
from datetime import datetime
from pathlib import Path

SBOMIT_DIR    = Path(__file__).parent.resolve()
SBOMIT_BIN    = SBOMIT_DIR / "sbomit"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def decode_payload(data):
    payload = data.get("payload", "")
    if isinstance(payload, str):
        try:
            return json.loads(base64.b64decode(payload + "=="))
        except Exception:
            return json.loads(base64.b64decode(payload))
    return payload


def normalize(module_set):
    """Normalize +incompatible / URL-encoded suffixes for comparison."""
    normalized = {}
    for entry in module_set:
        key = entry.replace("+incompatible", "").replace("%2Bincompatible", "").replace("%2bincompatible", "")
        normalized[key] = entry
    return normalized


# ─────────────────────────────────────────────────────────────────────────────
# Parse witness attestation by attestor type
# ─────────────────────────────────────────────────────────────────────────────

def parse_attestations_by_type(attestation_path):
    """Parse a witness attestation and return attestors indexed by short type name."""
    with open(attestation_path) as f:
        data = json.load(f)
    payload = decode_payload(data)
    attestations = payload.get("predicate", {}).get("attestations", [])
    by_type = {}
    for a in attestations:
        t = a.get("type", "")
        for short in ["material", "command-run", "product", "environment"]:
            if short in t:
                by_type[short] = a
                break
    return by_type


def extract_module_path(filepath):
    """Extract (module, version) from a Go module cache file path."""
    m = re.search(r'/go/pkg/mod/([a-zA-Z0-9._/\-]+@v[a-zA-Z0-9._\-]+)', filepath)
    if m:
        mm = re.match(r"(.+)@(v[^/]+)", m.group(1))
        if mm:
            return mm.group(1), mm.group(2)
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Extract modules from witness trace — per attestor and per process
# ─────────────────────────────────────────────────────────────────────────────

def extract_trace_modules(attestation_path):
    """
    Extract Go module@version from witness --trace attestation.
    Parses by attestor type (material vs command-run) and per process.

    Returns:
        trace_modules   - set of module@version strings
        version_map     - {module: set(versions)} for multi-version detection
        per_process     - list of {program, pid, cmdline, modules}
        attestor_times  - {attestor_type: {starttime, endtime, duration_s}}
        material_modules - modules seen in material attestor (pre-execution)
    """
    by_type = parse_attestations_by_type(attestation_path)

    trace_modules    = set()
    version_map      = collections.defaultdict(set)
    per_process      = []
    attestor_times   = {}
    material_modules = set()

    # Record timing for each attestor
    for atype, a in by_type.items():
        start = a.get("starttime", "")
        end   = a.get("endtime", "")
        duration = None
        if start and end:
            try:
                s = re.sub(r'(\.\d{6})\d+Z$', r'\1+00:00', start)
                e = re.sub(r'(\.\d{6})\d+Z$', r'\1+00:00', end)
                from datetime import datetime as dt
                duration = round(
                    (dt.fromisoformat(e) - dt.fromisoformat(s)).total_seconds(), 3
                )
            except Exception:
                pass
        attestor_times[atype] = {
            "starttime":  start,
            "endtime":    end,
            "duration_s": duration,
        }

    # Material attestor — files read BEFORE execution
    if "material" in by_type:
        for filepath in by_type["material"]["attestation"]:
            mod, ver = extract_module_path(filepath)
            if mod:
                key = f"{mod}@{ver}"
                material_modules.add(key)
                trace_modules.add(key)
                version_map[mod].add(ver)

    # Command-run attestor — per-process opened files (ptrace)
    if "command-run" in by_type:
        for proc in by_type["command-run"]["attestation"].get("processes", []):
            proc_modules = {}
            for filepath, digest in proc.get("openedfiles", {}).items():
                mod, ver = extract_module_path(filepath)
                if mod:
                    key = f"{mod}@{ver}"
                    proc_modules[key] = digest.get("sha256", "") if digest else ""
                    trace_modules.add(key)
                    version_map[mod].add(ver)
            if proc_modules:
                per_process.append({
                    "program":   proc.get("program", ""),
                    "pid":       proc.get("processid"),
                    "parentpid": proc.get("parentpid"),
                    "cmdline":   proc.get("cmdline", "")[:120],
                    "modules":   proc_modules,
                })

    return trace_modules, version_map, per_process, attestor_times, material_modules


# ─────────────────────────────────────────────────────────────────────────────
# Extract packages from SPDX SBOM (syft output)
# ─────────────────────────────────────────────────────────────────────────────

def extract_sbom_packages(sbom_path):
    """Extract Go module@version from an SPDX SBOM (syft generated)."""
    with open(sbom_path) as f:
        sbom = json.load(f)

    packages = set()
    for pkg in sbom.get("packages", []):
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                m = re.match(r"pkg:golang/(.+@v[^\s]+)", purl)
                if m:
                    val = m.group(1).replace("%2B", "+").replace("%2b", "+")
                    packages.add(val)
    return packages


# ─────────────────────────────────────────────────────────────────────────────
# Extract packages from sbomit SBOM output
# ─────────────────────────────────────────────────────────────────────────────

def extract_sbomit_packages(attestation_path):
    """
    Run sbomit generate on the attestation and extract packages.
    Returns (set of module@version, full sbomit SBOM dict)
    """
    if not SBOMIT_BIN.exists():
        print(f"ERROR: sbomit binary not found at {SBOMIT_BIN}")
        print("       Build it: cd ~/projects/sbomit && go build -o sbomit . && cp sbomit ~/SBOMIT/")
        sys.exit(1)

    result = subprocess.run(
        [str(SBOMIT_BIN), "generate", str(attestation_path), "--format", "spdx23"],
        capture_output=True, text=True
    )

    if result.returncode != 0 and not result.stdout.strip():
        print(f"ERROR: sbomit generate failed: {result.stderr}")
        sys.exit(1)

    # sbomit prints progress to stderr, SBOM JSON to stdout
    try:
        sbom = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: sbomit output is not valid JSON")
        print(result.stdout[:500])
        sys.exit(1)

    packages = set()
    for pkg in sbom.get("packages", []):
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                m = re.match(r"pkg:golang/(.+@v[^\s]+)", purl)
                if m:
                    val = m.group(1).replace("%2B", "+").replace("%2b", "+")
                    packages.add(val)

    return packages, sbom


# ─────────────────────────────────────────────────────────────────────────────
# Analysis 1: witness trace vs syft SBOM
# ─────────────────────────────────────────────────────────────────────────────

def analyze_trace_vs_syft(project, attestation_file, sbom_file):
    print(f"[1/2] Witness trace vs syft SBOM...")

    trace_modules, version_map, per_process, attestor_times, material_modules = \
        extract_trace_modules(attestation_file)
    sbom_packages = extract_sbom_packages(sbom_file)

    norm_trace = normalize(trace_modules)
    norm_sbom  = normalize(sbom_packages)
    trace_keys = set(norm_trace.keys())
    sbom_keys  = set(norm_sbom.keys())

    multi_ver = {k: sorted(v) for k, v in version_map.items() if len(v) > 1}

    # Per-process summary: top processes by number of modules opened
    proc_summary = sorted(
        [{"program": p["program"], "pid": p["pid"], "cmdline": p["cmdline"],
          "module_count": len(p["modules"])} for p in per_process],
        key=lambda x: x["module_count"], reverse=True
    )[:10]

    return {
        "analysis":             "trace_vs_syft",
        "trace_count":          len(trace_modules),
        "syft_count":           len(sbom_packages),
        "correctly_reported":   sorted(trace_keys & sbom_keys),
        "compiled_not_in_sbom": sorted(trace_keys - sbom_keys),
        "in_sbom_not_compiled": sorted(sbom_keys - trace_keys),
        "multi_version":        multi_ver,
        "attestor_timing":      attestor_times,
        "material_modules":     len(material_modules),
        "processes_traced":     len(per_process),
        "top_processes":        proc_summary,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Analysis 2: sbomit vs syft delta
# ─────────────────────────────────────────────────────────────────────────────

def analyze_sbomit_vs_syft(project, attestation_file, sbom_file):
    """
    Compare what sbomit extracts from the attestation vs what syft reports.
    This directly addresses Abhishek's suggestion: show how sbomit stands out
    compared to existing tools.
    """
    print(f"[2/2] sbomit vs syft delta...")

    sbomit_packages, sbomit_sbom = extract_sbomit_packages(attestation_file)
    syft_packages = extract_sbom_packages(sbom_file)

    norm_sbomit = normalize(sbomit_packages)
    norm_syft   = normalize(syft_packages)
    sbomit_keys = set(norm_sbomit.keys())
    syft_keys   = set(norm_syft.keys())

    # Quality comparison: check checksums and primaryPackagePurpose
    sbomit_with_checksum = sum(
        1 for pkg in sbomit_sbom.get("packages", [])
        if pkg.get("checksums")
    )
    sbomit_with_purpose = sum(
        1 for pkg in sbomit_sbom.get("packages", [])
        if pkg.get("primaryPackagePurpose") and pkg.get("primaryPackagePurpose") != "UNSET"
    )
    sbomit_total = len(sbomit_sbom.get("packages", []))

    return {
        "analysis":                 "sbomit_vs_syft",
        "sbomit_count":             len(sbomit_packages),
        "syft_count":               len(syft_packages),
        "in_both":                  sorted(sbomit_keys & syft_keys),
        "sbomit_only":              sorted(sbomit_keys - syft_keys),   # sbomit finds more
        "syft_only":                sorted(syft_keys - sbomit_keys),   # syft finds more
        "sbomit_packages_total":    sbomit_total,
        "sbomit_with_checksum":     sbomit_with_checksum,
        "sbomit_with_purpose":      sbomit_with_purpose,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis runner
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis(project, attestation_file=None, sbom_file=None,
                 compare_catalogs=False):
    if attestation_file is None:
        attestation_file = SBOMIT_DIR / "attestations" / project / "build.json"
    if sbom_file is None:
        sbom_file = SBOMIT_DIR / "sboms" / f"sbom-{project}-rich.spdx.json"

    attestation_file = Path(attestation_file)
    sbom_file        = Path(sbom_file)

    if not attestation_file.exists():
        print(f"ERROR: Attestation not found: {attestation_file}")
        print(f"       Run a Deep run for {project} first.")
        sys.exit(1)
    if not sbom_file.exists():
        print(f"ERROR: SBOM not found: {sbom_file}")
        print(f"       Run any pipeline for {project} first.")
        sys.exit(1)

    print(f"Project:     {project}")
    print(f"Attestation: {attestation_file}")
    print(f"SBOM:        {sbom_file}")
    print()

    result = {
        "project":          project,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "attestation_file": str(attestation_file),
        "sbom_file":        str(sbom_file),
    }

    result["trace_vs_syft"] = analyze_trace_vs_syft(
        project, attestation_file, sbom_file
    )

    if compare_catalogs:
        result["sbomit_vs_syft"] = analyze_sbomit_vs_syft(
            project, attestation_file, sbom_file
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Output formatters
# ─────────────────────────────────────────────────────────────────────────────

def print_text(r):
    print("=" * 65)
    print(f"DISAMBIGUATION REPORT \u2014 {r['project']}")
    print(f"Generated: {r['timestamp']}")
    print("=" * 65)

    # ── Analysis 1: trace vs syft ──────────────────────────────────────────
    t = r["trace_vs_syft"]
    print()
    print("\u25b6  WITNESS TRACE vs SYFT SBOM")
    print(f"   Modules compiled (witness trace): {t['trace_count']}")
    print(f"   Packages in SBOM (syft):          {t['syft_count']}")
    print(f"   Correctly reported in both:       {len(t['correctly_reported'])}")
    print(f"   Processes traced:                 {t.get('processes_traced', 'n/a')}")
    print(f"   Modules seen in material phase:   {t.get('material_modules', 'n/a')}")
    print()

    # Attestor timing
    timing = t.get("attestor_timing", {})
    if timing:
        print("   Attestor timing:")
        for atype, info in sorted(timing.items()):
            d = info.get("duration_s")
            dur = f"{d}s" if d is not None else "n/a"
            print(f"     {atype:<15} start={info['starttime'][:19]}  duration={dur}")
    print()

    # Top processes by module usage
    top = t.get("top_processes", [])
    if top:
        print("   Top processes by modules opened:")
        for p in top[:5]:
            prog = p['program'].split('/')[-1]
            print(f"     [{p['module_count']:3d} modules] {prog}  — {p['cmdline'][:60]}")
    print()

    if t["multi_version"]:
        print(f"\u26a0\ufe0f  MULTI-VERSION CONFLICTS ({len(t['multi_version'])}):")
        for mod, vers in sorted(t["multi_version"].items()):
            print(f"   {mod}")
            for v in vers:
                print(f"     \u2192 {v}")
    else:
        print("\u2705 No multi-version conflicts")
    print()

    if t["compiled_not_in_sbom"]:
        print(f"\u26a0\ufe0f  COMPILED BUT MISSING FROM SBOM ({len(t['compiled_not_in_sbom'])}):")
        for m in t["compiled_not_in_sbom"]:
            print(f"   - {m}")
    else:
        print("\u2705 No compiled modules missing from SBOM")
    print()

    if t["in_sbom_not_compiled"]:
        print(f"\u26a0\ufe0f  IN SBOM BUT NEVER COMPILED ({len(t['in_sbom_not_compiled'])}) \u2014 potential CVE false positives:")
        for m in t["in_sbom_not_compiled"]:
            print(f"   - {m}")
    else:
        print("\u2705 No over-reported packages in SBOM")
    print()

    # ── Analysis 2: sbomit vs syft ─────────────────────────────────────────
    if "sbomit_vs_syft" in r:
        s = r["sbomit_vs_syft"]
        print("=" * 65)
        print("\u25b6  SBOMIT vs SYFT DELTA")
        print(f"   Packages found by sbomit: {s['sbomit_count']}")
        print(f"   Packages found by syft:   {s['syft_count']}")
        print(f"   Found by both:            {len(s['in_both'])}")
        print()
        print(f"   sbomit SBOM quality:")
        print(f"     Total packages:         {s['sbomit_packages_total']}")
        print(f"     With SHA256 checksum:   {s['sbomit_with_checksum']}/{s['sbomit_packages_total']}")
        print(f"     With package purpose:   {s['sbomit_with_purpose']}/{s['sbomit_packages_total']}")
        print()

        if s["sbomit_only"]:
            print(f"\u2728  SBOMIT FINDS BUT SYFT MISSES ({len(s['sbomit_only'])}) \u2014 sbomit advantage:")
            for m in s["sbomit_only"][:20]:
                print(f"   + {m}")
            if len(s["sbomit_only"]) > 20:
                print(f"   ... ({len(s['sbomit_only'])} total)")
        print()

        if s["syft_only"]:
            print(f"\u26a0\ufe0f  SYFT FINDS BUT SBOMIT MISSES ({len(s['syft_only'])}):")
            for m in s["syft_only"][:20]:
                print(f"   - {m}")
            if len(s["syft_only"]) > 20:
                print(f"   ... ({len(s['syft_only'])} total)")
        print()

    print("=" * 65)


def print_csv(r, output_path):
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["module", "in_trace", "in_syft_sbom", "in_sbomit_sbom", "status"])

        t = r["trace_vs_syft"]
        s = r.get("sbomit_vs_syft", {})
        sbomit_set = set(s.get("in_both", []) + s.get("sbomit_only", []))
        syft_set   = set(t["correctly_reported"] + t["in_sbom_not_compiled"])

        all_modules = set(
            t["correctly_reported"] +
            t["compiled_not_in_sbom"] +
            t["in_sbom_not_compiled"] +
            list(sbomit_set)
        )

        for mod in sorted(all_modules):
            in_trace  = mod in set(t["correctly_reported"] + t["compiled_not_in_sbom"])
            in_syft   = mod in syft_set
            in_sbomit = mod in sbomit_set

            if in_trace and in_syft:
                status = "correct"
            elif in_trace and not in_syft:
                status = "missing_from_syft_sbom"
            elif not in_trace and in_syft:
                status = "over_reported_by_syft"
            elif in_sbomit and not in_syft:
                status = "sbomit_advantage"
            else:
                status = "syft_only"

            writer.writerow([mod, in_trace, in_syft, in_sbomit, status])

    print(f"CSV saved to: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Disambiguate witness trace vs SBOM, and compare sbomit vs syft"
    )
    parser.add_argument("--project",          required=True,
                        help="Project name (gittuf, flux2, kyverno, ...)")
    parser.add_argument("--attestation",      default=None,
                        help="Path to build.json attestation (default: auto)")
    parser.add_argument("--sbom",             default=None,
                        help="Path to syft SBOM JSON (default: auto)")
    parser.add_argument("--compare-catalogs", action="store_true",
                        help="Also run sbomit vs syft delta analysis")
    parser.add_argument("--format",           default="text",
                        choices=["text", "json", "csv"],
                        help="Output format (default: text)")
    parser.add_argument("--output",           default=None,
                        help="Output file path (default: stdout)")
    args = parser.parse_args()

    result = run_analysis(
        args.project,
        args.attestation,
        args.sbom,
        args.compare_catalogs,
    )

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
        output_path = args.output or f"disambiguate-{args.project}.csv"
        print_csv(result, output_path)


if __name__ == "__main__":
    main()
