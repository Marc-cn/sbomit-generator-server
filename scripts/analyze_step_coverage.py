#!/usr/bin/env python3
"""
analyze_step_coverage.py — 가설 검증 분석 스크립트

가설: "build/install step만 trace해도 모든 step trace와 동일한 패키지를 잡을 수 있다"

사용법:
  python3 scripts/analyze_step_coverage.py attestations/sbomit/
  python3 scripts/analyze_step_coverage.py attestations/sbomit/ --build-only-keywords build,install,compile
"""

import json
import re
import base64
import argparse
from pathlib import Path


PATTERNS = {
    "go": re.compile(r'.*/go/pkg/mod/([^@/]+(?:/[^@/]+)*)@([^/]+)'),
    "python": re.compile(r'.*/site-packages/([A-Za-z0-9_.+-]+)-([0-9][^/]*)\.dist-info/'),
    "rust": re.compile(r'.*/.cargo/registry/(?:cache|src)/[^/]+/(.+)-([0-9][0-9.]+[^/]*)\.crate$'),
}


def extract_packages_from_attestation(attestation_path):
    """하나의 attestation 파일에서 ptrace로 잡힌 패키지를 추출."""
    packages = set()
    
    try:
        envelope = json.loads(attestation_path.read_text())
        payload = envelope.get("payload", "")
        if not payload:
            return packages
        
        decoded = json.loads(base64.b64decode(payload))
        
        for a in decoded.get("predicate", {}).get("attestations", []):
            if "command-run" not in a.get("type", ""):
                continue
            
            for proc in a.get("attestation", {}).get("processes", []):
                for fpath in proc.get("openedfiles", {}).keys():
                    m = PATTERNS["go"].match(fpath)
                    if m and not m.group(1).startswith("cache/"):
                        packages.add(f"pkg:golang/{m.group(1)}@{m.group(2)}")
                        continue
                    
                    m = PATTERNS["python"].match(fpath)
                    if m:
                        name = m.group(1).lower().replace("-", "_")
                        packages.add(f"pkg:pypi/{name}@{m.group(2)}")
                        continue
                    
                    m = PATTERNS["rust"].match(fpath)
                    if m:
                        packages.add(f"pkg:cargo/{m.group(1)}@{m.group(2)}")
                        continue
    except Exception as e:
        print(f"  [warning] Failed to parse {attestation_path.name}: {e}")
    
    return packages


def is_build_step(step_name, keywords):
    step_lower = step_name.lower()
    return any(kw in step_lower for kw in keywords)


def analyze_project(attest_dir, build_keywords):
    attest_dir = Path(attest_dir)
    if not attest_dir.is_dir():
        print(f"ERROR: {attest_dir} is not a directory")
        return
    
    json_files = sorted(attest_dir.glob("*.json"))
    if not json_files:
        print(f"ERROR: No JSON files found in {attest_dir}")
        return
    
    project_name = attest_dir.name
    print(f"\n{'='*70}")
    print(f"  Project: {project_name}")
    print(f"  Attestations dir: {attest_dir}")
    print(f"  Files found: {len(json_files)}")
    print(f"  Build keywords: {build_keywords}")
    print(f"{'='*70}\n")
    
    # Step별 패키지 추출
    step_packages = {}
    for jf in json_files:
        step_name = jf.stem
        packages = extract_packages_from_attestation(jf)
        step_packages[step_name] = packages
        
        is_build = is_build_step(step_name, build_keywords)
        marker = "BUILD" if is_build else "other"
        print(f"  [{marker:5s}] {step_name:30s} -> {len(packages):4d} packages")
    
    # Union 계산
    all_union = set()
    for pkgs in step_packages.values():
        all_union |= pkgs
    
    build_only_union = set()
    for step_name, pkgs in step_packages.items():
        if is_build_step(step_name, build_keywords):
            build_only_union |= pkgs
    
    missed_by_build_only = all_union - build_only_union
    
    # 결과 출력
    print(f"\n{'-'*70}")
    print(f"  ANALYSIS RESULTS")
    print(f"{'-'*70}")
    print(f"  Total unique packages (all steps):  {len(all_union)}")
    print(f"  Build/install only union:           {len(build_only_union)}")
    coverage = len(build_only_union)/len(all_union)*100 if all_union else 0
    print(f"  Coverage ratio:                     {coverage:.1f}%")
    print(f"  Missed by build-only:               {len(missed_by_build_only)}")
    
    if missed_by_build_only:
        print(f"\n  Packages missed if we only trace build/install:")
        for pkg in sorted(missed_by_build_only):
            found_in = [s for s, p in step_packages.items() if pkg in p]
            print(f"     - {pkg}")
            print(f"       (found in: {', '.join(found_in)})")
    else:
        print(f"\n  *** Hypothesis CONFIRMED for {project_name}: "
              f"build-only covers all packages! ***")
    
    # Step별 unique 기여도
    print(f"\n  Step-specific unique packages:")
    for step_name, pkgs in step_packages.items():
        unique_to_step = pkgs.copy()
        for other_step, other_pkgs in step_packages.items():
            if other_step != step_name:
                unique_to_step -= other_pkgs
        if unique_to_step:
            print(f"     {step_name}: {len(unique_to_step)} unique packages")
            for pkg in sorted(unique_to_step)[:5]:
                print(f"        - {pkg}")
            if len(unique_to_step) > 5:
                print(f"        ... and {len(unique_to_step)-5} more")
        else:
            print(f"     {step_name}: 0 unique packages")
    
    print()
    return {
        "project": project_name,
        "step_packages": {k: sorted(list(v)) for k, v in step_packages.items()},
        "all_union": sorted(list(all_union)),
        "build_only_union": sorted(list(build_only_union)),
        "missed_by_build_only": sorted(list(missed_by_build_only)),
        "coverage_ratio": coverage / 100,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("attest_dir", help="Path to attestations/{project}/ directory")
    parser.add_argument("--build-only-keywords", default="build,install,compile",
                        help="Comma-separated keywords for build steps")
    parser.add_argument("--output-json", default=None, help="Save results as JSON")
    args = parser.parse_args()
    
    keywords = [k.strip() for k in args.build_only_keywords.split(",")]
    result = analyze_project(args.attest_dir, keywords)
    
    if args.output_json and result:
        Path(args.output_json).write_text(json.dumps(result, indent=2))
        print(f"  Results saved to: {args.output_json}\n")

if __name__ == "__main__":
    main()
