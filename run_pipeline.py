#!/usr/bin/env python3
"""
run_pipeline.py — Unified witness attestation runner.

Replaces run_pipeline.sh + parse_makefile.py in a single maintainable Python file.

Usage:
    python3 run_pipeline.py --project-dir projects/gittuf
    python3 run_pipeline.py --project-dir projects/gittuf --skip-targets "test,install"
    python3 run_pipeline.py --project-dir projects/gittuf --mode deep
    python3 run_pipeline.py --project-dir projects/tuf --mode quick
"""

import sys
import os
import re
import json
import argparse
import subprocess
from pathlib import Path

import shutil

# ── Directory layout ──────────────────────────────────────────────────────────
SBOMIT_DIR   = Path(__file__).parent.resolve()
WITNESS      = shutil.which("witness") or (SBOMIT_DIR / "witness")
SIGNING_KEY  = SBOMIT_DIR / "signing.key"

# ── Targets never worth attesting ─────────────────────────────────────────────
GLOBAL_SKIP = {
    "help", "all", "clean", "distclean", "mrproper",
    ".PHONY", ".DEFAULT", ".SUFFIXES",
}

# ── Per-project targets to skip ───────────────────────────────────────────────
PROJECT_SKIP = {
    "kyverno": {
        "install-tools", "build-images", "ko-build", "docker-build",
        "kind-create-cluster", "kind-delete-cluster", "deploy",
    },
    "argo-cd": {
        "mockgen", "gogen", "protogen", "protogen-fast", "openapigen",
        "clientgen", "clidocsgen", "actionsdocsgen", "resourceiconsgen",
        "codegen", "codegen-local", "codegen-local-fast",
        "notification-catalog", "notification-docs",
        "build-ui", "dep-ui", "dep-ui-local", "lint-ui", "lint-ui-local",
        "image", "armimage", "builder-image", "test-tools-image",
        "test-e2e", "test-e2e-local", "start-e2e", "start-e2e-local",
        "debug-test-server", "debug-test-client", "start-test-k8s",
        "install-tools-local", "install-test-tools-local",
        "install-codegen-tools-local", "install-go-tools-local",
        "release", "release-cli", "release-precheck",
        "build-docs", "build-docs-local", "serve-docs", "serve-docs-local",
        "manifests", "manifests-local",
        "checksums", "snyk-container-tests", "snyk-non-container-tests",
        "snyk-report", "list", "start", "start-local", "run",
        "mod-vendor", "mod-vendor-local",
    },
    "flux2": {
        "setup-kind", "cleanup-kind", "e2e", "test-with-kind",
        "install-envtest", "setup-envtest", "envtest",
        "setup-bootstrap-patch", "setup-image-automation",
    },
    "protobom": {
        "proto",
        "help", "conformance-test", "conformance", "fakes", "buf-format", "buf-lint",
    }
}

# ── Steps that must NOT use --trace ───────────────────────────────────────────
NO_TRACE_STEPS = {"test", "go-test", "install-tools"}

# ── Steps that use --trace only in deep mode ──────────────────────────────────
DEEP_TRACE_STEPS = {"build", "install"}


# ─────────────────────────────────────────────────────────────────────────────
# Makefile / tox parsing (previously parse_makefile.py)
# ─────────────────────────────────────────────────────────────────────────────

def _expand_brace(s):
    """Expand shell brace expressions: py{38,39,310} → [py38, py39, py310]."""
    m = re.search(r'\{([^{}]+)\}', s)
    if not m:
        return [s]
    prefix, suffix = s[:m.start()], s[m.end():]
    results = []
    for alt in m.group(1).split(','):
        for expanded in _expand_brace(prefix + alt.strip() + suffix):
            results.append(expanded)
    return results


def _is_fake_target(target):
    """Return True for ALL_CAPS Makefile variable definitions, not real targets."""
    if re.match(r'^[A-Z][A-Z0-9_]+$', target):
        return True
    return False


def parse_makefile(path, project_name=None):
    """Parse Makefile and return dict of {target: [commands]}."""
    try:
        content = Path(path).read_text()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return {}

    skip_set = set(GLOBAL_SKIP)
    if project_name and project_name in PROJECT_SKIP:
        skip_set |= PROJECT_SKIP[project_name]

    targets = {}

    # Collect .PHONY declarations
    phony = set()
    for m in re.finditer(r'^\.PHONY\s*:\s*(.+)$', content, re.MULTILINE):
        for t in m.group(1).split():
            phony.add(t.strip())

    # Collect explicit target definitions
    for m in re.finditer(r'^([a-zA-Z0-9_./-]+)\s*:', content, re.MULTILINE):
        if m.group(1) not in targets:
            targets[m.group(1)] = []

    # Add PHONY targets even if not explicitly defined
    for t in phony:
        if t not in targets:
            targets[t] = []

    # Parse recipe lines
    current_target = None
    for line in content.split('\n'):
        m = re.match(r'^([a-zA-Z0-9_./-]+)\s*:', line)
        if m:
            current_target = m.group(1)
            if current_target not in targets:
                targets[current_target] = []
        elif line.startswith('\t') and current_target:
            cmd = line.strip()
            if cmd and not cmd.startswith('#'):
                targets[current_target].append(cmd)

    # Filter fake / skipped targets
    return {
        t: cmds for t, cmds in targets.items()
        if t not in skip_set and not _is_fake_target(t)
    }


def parse_tox(path):
    """Parse tox.ini and return sorted list of environment names."""
    try:
        content = Path(path).read_text()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return []

    envs = set()

    # Named [testenv:name] sections
    for m in re.finditer(r'^\[testenv:([^\]]+)\]', content, re.MULTILINE):
        envs.add(m.group(1).strip())

    # envlist lines with brace expansion
    envlist_block = re.search(
        r'^envlist\s*=\s*(.+?)(?=^\S|\Z)', content,
        re.MULTILINE | re.DOTALL
    )
    if envlist_block:
        raw = re.sub(r'#[^\n]*', '', envlist_block.group(1))
        raw = raw.replace('\\\n', ' ')
        for token in re.split(r'[\s,]+', raw):
            token = token.strip()
            if token:
                for expanded in _expand_brace(token):
                    if expanded:
                        envs.add(expanded)

    return sorted(envs)


# ─────────────────────────────────────────────────────────────────────────────
# Witness invocation
# ─────────────────────────────────────────────────────────────────────────────

def get_trace_flag(step_name, mode):
    """Determine whether --trace should be passed for this step."""
    step_lower = step_name.lower()
    if step_name in NO_TRACE_STEPS or "test" in step_lower or "lint" in step_lower or "vet" in step_lower:
        return None
    if step_name in DEEP_TRACE_STEPS or "build" in step_lower or "install" in step_lower:
        return "--trace" if mode == "deep" else None
    return "--trace"  # default: trace all other steps (fmt, tidy, vet, etc.)


def parse_attestation_timing(out_file):
    """
    Read a completed attestation file and print a timing summary per attestor.
    Shows starttime, endtime, and duration for each attestor phase.
    """
    try:
        import base64
        with open(out_file) as f:
            data = json.load(f)
        payload_raw = data.get("payload", "")
        if isinstance(payload_raw, str):
            try:
                payload = json.loads(base64.b64decode(payload_raw + "=="))
            except Exception:
                payload = json.loads(base64.b64decode(payload_raw))
        else:
            payload = payload_raw

        attestations = payload.get("predicate", {}).get("attestations", [])
        if not attestations:
            return

        print("  Attestor timing:")
        for a in attestations:
            atype = a.get("type", "")
            # Extract short name: environment, material, command-run, product
            short = atype.split("/")[-2] if "/" in atype else atype
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
            start_short = start[:19].replace("T", " ") if start else "n/a"
            dur_str = f"{duration}s" if duration is not None else "n/a"
            print(f"    {short:<15} start={start_short}  duration={dur_str}")
    except Exception as e:
        pass  # timing is informational, never block the pipeline


def run_step(step_name, cmd, attestation_dir, mode, skip_set):
    """Attest a single build step with witness."""
    if step_name in skip_set:
        print(f"SKIP: {step_name}")
        return

    out_file = attestation_dir / f"{step_name}.json"
    print(f"ATTESTING: {step_name}")

    # Clear Go test cache before test steps to ensure fresh attestation
    if step_name in ("test", "go-test") or "test" in step_name.lower():
        subprocess.run(["go", "clean", "-testcache"], capture_output=True)

    trace_flag = get_trace_flag(step_name, mode)

    witness_cmd = [
        str(WITNESS), "run",
        "--step", step_name,
        "--signer-file-key-path", str(SIGNING_KEY),
        "--attestations", "environment",
    ]
    if trace_flag:
        witness_cmd.append(trace_flag)
        
    cmd_parts = cmd.split()
    if cmd_parts and cmd_parts[0] == "make" and step_name != "test" and "test" not in step_name.lower():
        # Tell Make to assume 'test' is up-to-date to prevent recursive testing
        cmd_parts.extend(['-o', 'test'])

    witness_cmd += ["-o", str(out_file), "--"] + cmd_parts

    subprocess.run(witness_cmd)

    if out_file.exists():
        size = subprocess.check_output(["du", "-h", str(out_file)]).decode().split()[0]
        print(f"OK: {step_name} ({size})")
        parse_attestation_timing(out_file)
    else:
        print(f"FAIL: {step_name} — output file not written")


# ─────────────────────────────────────────────────────────────────────────────
# Go module cache pre-warming
# ─────────────────────────────────────────────────────────────────────────────

def warm_go_cache(project_dir):
    """Run go mod download to populate the module cache before attestation."""
    if (project_dir / "go.mod").exists():
        print("Pre-warming Go module cache...")
        result = subprocess.run(
            ["go", "mod", "download"],
            cwd=project_dir,
            capture_output=True, text=True
        )
        # Only print last few lines to avoid flooding the log
        lines = (result.stdout + result.stderr).strip().splitlines()
        for line in lines[-5:]:
            print(line)
        print("Go cache ready.")


# ─────────────────────────────────────────────────────────────────────────────
# Build system detection and pipeline execution
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline(project_dir, skip_targets, mode, prewarm=False):
    """Detect build system and run witness attestation on each target."""
    project_name = project_dir.name
    attestation_dir = SBOMIT_DIR / "attestations" / project_name
    attestation_dir.mkdir(parents=True, exist_ok=True)

    # Build skip set from CLI + project-specific overrides
    skip_set = set(t.strip() for t in skip_targets.split(",") if t.strip())

    os.chdir(project_dir)

    if (project_dir / "Makefile").exists():
        print("Detected: Makefile")
        if prewarm:
            warm_go_cache(project_dir)
        targets = parse_makefile(project_dir / "Makefile", project_name)
        if not targets:
            print("WARNING: no valid targets found in Makefile")
        for target in targets:
            run_step(target, f"make {target}", attestation_dir, mode, skip_set)
        
        # If it's a Go project but its Makefile doesn't explicitly have a build target,
        # we still want to ensure the actual code gets compiled and attested.
        if (project_dir / "go.mod").exists() and "build" not in targets and "go-build" not in skip_set:
            print("Notice: Makefile lacks 'build' target. Injecting standard 'go build' for go.mod")
            run_step("go-build", "go build ./...", attestation_dir, mode, skip_set)

    elif (project_dir / "tox.ini").exists():
        print("Detected: tox.ini")
        envs = parse_tox(project_dir / "tox.ini")
        if not envs:
            run_step("tox", "tox", attestation_dir, mode, skip_set)
        else:
            for env in envs:
                run_step(env, f"tox -e {env}", attestation_dir, mode, skip_set)

    elif (project_dir / "go.mod").exists():
        print("Detected: go.mod (no Makefile)")
        if prewarm:
            warm_go_cache(project_dir)
        run_step("go-build", "go build ./...", attestation_dir, mode, skip_set)
        run_step("go-test",  "go test ./...",  attestation_dir, mode, skip_set)
        run_step("go-fmt",   "gofmt -l .",     attestation_dir, mode, skip_set)

    elif (project_dir / "pyproject.toml").exists():
        print("Detected: pyproject.toml")
        run_step("python-build", "python3 -m build", attestation_dir, mode, skip_set)

    else:
        print(f"ERROR: No recognized build system in {project_dir}")
        sys.exit(1)

    print(f"\nDone. Attestations saved to: {attestation_dir}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Witness attestation pipeline runner"
    )
    parser.add_argument("--project-dir", required=True,
                        help="Project directory (relative to SBOMIT_DIR or absolute)")
    parser.add_argument("--skip-targets", default="",
                        help="Comma-separated list of targets to skip")
    parser.add_argument("--mode", default="quick",
                        choices=["quick", "full", "deep"],
                        help="Run mode: quick, full, or deep (default: quick)")
    parser.add_argument("--prewarm", action="store_true", default=False,
                        help="Pre-warm Go module cache before attestation (go mod download). "
                             "Useful for offline builds but changes file access patterns. "
                             "Disable to capture go mod download in network attestor.")
    args = parser.parse_args()

    # Resolve project directory
    project_dir = Path(args.project_dir)
    if not project_dir.is_absolute():
        project_dir = SBOMIT_DIR / project_dir
    if not project_dir.exists():
        print(f"ERROR: Project directory not found: {project_dir}")
        sys.exit(1)

    print(f"Project:  {project_dir}")
    print(f"Mode:     {args.mode}")
    if args.skip_targets:
        print(f"Skipping: {args.skip_targets}")
    print()

    run_pipeline(project_dir, args.skip_targets, args.mode, args.prewarm)


if __name__ == "__main__":
    main()
