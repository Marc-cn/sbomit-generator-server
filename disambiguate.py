#!/usr/bin/env python3
"""
disambiguate.py — Cross-reference witness --trace attestation with SBOM packages.

Usage:
    python3 disambiguate.py --project gittuf
    python3 disambiguate.py --project flux2
    python3 disambiguate.py --project gittuf --attestation build.json --output report.json
    python3 disambiguate.py --project gittuf --format text|json|csv

Requires:
    - ~/SBOMIT/attestations/<project>/build.json (from a Deep run)
    - ~/SBOMIT/sboms/sbom-<project>-rich.spdx.json
"""
import json, re, base64, collections, argparse, sys, os, csv
from datetime import datetime

SBOMIT_DIR = os.path.expanduser("~/SBOMIT")


def decode_payload(data):
    payload = data.get('payload', '')
    if isinstance(payload, str):
        try:
            return json.loads(base64.b64decode(payload + '=='))
        except Exception:
            return json.loads(base64.b64decode(payload))
    return payload


def extract_trace_modules(attestation_path):
    """Extract all Go module@version paths from a witness --trace attestation."""
    with open(attestation_path) as f:
        data = json.load(f)
    payload = decode_payload(data)
    raw = json.dumps(payload)

    paths = re.findall(
        r'/home/\w+/go/pkg/mod/([a-zA-Z0-9._/\-]+@v[a-zA-Z0-9._\-]+)', raw
    )

    versions = collections.defaultdict(set)
    trace_modules = set()

    for path in paths:
        m = re.match(r'(.+)@(v[^/]+)', path)
        if m:
            mod, ver = m.group(1), m.group(2)
            trace_modules.add(f"{mod}@{ver}")
            versions[mod].add(ver)

    return trace_modules, versions


def extract_sbom_packages(sbom_path):
    """Extract Go module@version from an SPDX SBOM."""
    with open(sbom_path) as f:
        sbom = json.load(f)

    sbom_packages = set()
    for pkg in sbom.get('packages', []):
        for ref in pkg.get('externalRefs', []):
            if ref.get('referenceType') == 'purl':
                purl = ref.get('referenceLocator', '')
                m = re.match(r'pkg:golang/(.+@v[^\s]+)', purl)
                if m:
                    # normalize URL encoding
                    val = m.group(1).replace('%2B', '+').replace('%2b', '+')
                    sbom_packages.add(val)
    return sbom_packages


def normalize(module_set):
    """Normalize +incompatible suffix for comparison."""
    normalized = {}
    for entry in module_set:
        key = entry.replace('+incompatible', '').replace('%2Bincompatible', '')
        normalized[key] = entry
    return normalized


def run_analysis(project, attestation_file=None, sbom_file=None):
    # Resolve paths
    if attestation_file is None:
        attestation_file = os.path.join(
            SBOMIT_DIR, 'attestations', project, 'build.json'
        )
    if sbom_file is None:
        sbom_file = os.path.join(
            SBOMIT_DIR, 'sboms', f'sbom-{project}-rich.spdx.json'
        )

    # Check files exist
    if not os.path.exists(attestation_file):
        print(f"ERROR: Attestation not found: {attestation_file}")
        print(f"       Run a Deep run for {project} first.")
        sys.exit(1)
    if not os.path.exists(sbom_file):
        print(f"ERROR: SBOM not found: {sbom_file}")
        print(f"       Run any pipeline for {project} first.")
        sys.exit(1)

    print(f"Analyzing project: {project}")
    print(f"Attestation:       {attestation_file}")
    print(f"SBOM:              {sbom_file}")
    print()

    # Extract data
    trace_modules, version_map = extract_trace_modules(attestation_file)
    sbom_packages = extract_sbom_packages(sbom_file)

    # Normalize for comparison
    norm_trace = normalize(trace_modules)
    norm_sbom  = normalize(sbom_packages)

    trace_keys = set(norm_trace.keys())
    sbom_keys  = set(norm_sbom.keys())

    # Results
    both        = trace_keys & sbom_keys
    only_trace  = trace_keys - sbom_keys
    only_sbom   = sbom_keys  - trace_keys
    multi_ver   = {k: sorted(v) for k, v in version_map.items() if len(v) > 1}

    return {
        "project":          project,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "attestation_file": attestation_file,
        "sbom_file":        sbom_file,
        "trace_count":      len(trace_modules),
        "sbom_count":       len(sbom_packages),
        "correctly_reported": sorted(both),
        "compiled_not_in_sbom": sorted(only_trace),
        "in_sbom_not_compiled": sorted(only_sbom),
        "multi_version":    multi_ver,
    }


def print_text(r):
    print("=" * 60)
    print(f"DISAMBIGUATION REPORT — {r['project']}")
    print(f"Generated: {r['timestamp']}")
    print("=" * 60)
    print(f"  Modules actually compiled (witness trace): {r['trace_count']}")
    print(f"  Packages in SBOM (syft):                   {r['sbom_count']}")
    print(f"  Correctly reported in both:                {len(r['correctly_reported'])}")
    print()

    if r['multi_version']:
        print(f"⚠️  MULTI-VERSION CONFLICTS ({len(r['multi_version'])}):")
        for mod, vers in sorted(r['multi_version'].items()):
            print(f"  {mod}")
            for v in vers:
                print(f"    -> {v}")
        print()
    else:
        print("✅ No multi-version conflicts — all modules compiled at single version")
        print()

    if r['compiled_not_in_sbom']:
        print(f"⚠️  COMPILED BUT MISSING FROM SBOM ({len(r['compiled_not_in_sbom'])}):")
        print("   These were used at build time but syft didn't report them:")
        for m in r['compiled_not_in_sbom']:
            print(f"  - {m}")
        print()
    else:
        print("✅ No compiled modules missing from SBOM")
        print()

    if r['in_sbom_not_compiled']:
        print(f"⚠️  IN SBOM BUT NEVER COMPILED ({len(r['in_sbom_not_compiled'])}):")
        print("   Syft over-reported — these were never opened by the compiler:")
        print("   (Could be false positives in CVE scans)")
        for m in r['in_sbom_not_compiled']:
            print(f"  - {m}")
        print()
    else:
        print("✅ No over-reported packages in SBOM")
        print()

    print("=" * 60)


def print_csv(r, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['module', 'status', 'note'])
        for m in r['correctly_reported']:
            writer.writerow([m, 'ok', 'compiled and in SBOM'])
        for m in r['compiled_not_in_sbom']:
            writer.writerow([m, 'missing_from_sbom', 'compiled but syft missed it'])
        for m in r['in_sbom_not_compiled']:
            writer.writerow([m, 'over_reported', 'in SBOM but never compiled'])
        for mod, vers in r['multi_version'].items():
            writer.writerow([mod, 'multi_version', ', '.join(vers)])
    print(f"CSV saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Disambiguate witness trace vs SBOM packages"
    )
    parser.add_argument('--project',     required=True,
                        help='Project name (gittuf, flux2, kyverno, ...)')
    parser.add_argument('--attestation', default=None,
                        help='Path to build.json attestation (default: auto)')
    parser.add_argument('--sbom',        default=None,
                        help='Path to SBOM JSON file (default: auto)')
    parser.add_argument('--format',      default='text',
                        choices=['text', 'json', 'csv'],
                        help='Output format (default: text)')
    parser.add_argument('--output',      default=None,
                        help='Output file path (default: stdout for text/json)')
    args = parser.parse_args()

    result = run_analysis(args.project, args.attestation, args.sbom)

    if args.format == 'text':
        print_text(result)
        if args.output:
            with open(args.output, 'w') as f:
                # redirect print to file
                import io, contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    print_text(result)
                f.write(buf.getvalue())
            print(f"Report saved to: {args.output}")

    elif args.format == 'json':
        out = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(out)
            print(f"JSON saved to: {args.output}")
        else:
            print(out)

    elif args.format == 'csv':
        output_path = args.output or f"disambiguate-{args.project}.csv"
        print_csv(result, output_path)


if __name__ == '__main__':
    main()
