#!/usr/bin/env python3
import sys
import json
import re
import itertools


# ── Targets that are never worth attesting ──────────────────────────────────
GLOBAL_SKIP = {
    "help", "all", "clean", "distclean", "mrproper",
    ".PHONY", ".DEFAULT", ".SUFFIXES",
}

# Per-project targets to skip (infrastructure / env-setup / too slow)
PROJECT_SKIP = {
    "kyverno": {
        "install-tools", "build-images", "ko-build", "docker-build",
        "kind-create-cluster", "kind-delete-cluster", "deploy",
    },
}


def _expand_brace(s):
    """Expand shell-style brace expressions: py{38,39,310} → [py38, py39, py310]."""
    m = re.search(r'\{([^{}]+)\}', s)
    if not m:
        return [s]
    prefix = s[:m.start()]
    suffix = s[m.end():]
    alternatives = m.group(1).split(',')
    results = []
    for alt in alternatives:
        for expanded in _expand_brace(prefix + alt.strip() + suffix):
            results.append(expanded)
    return results


def _is_fake_target(target):
    """
    Return True for targets that are clearly Makefile variable definitions,
    not real build targets.

    Heuristics:
      - ALL_CAPS_WITH_UNDERSCORES  →  almost always a variable
      - Contains path separators or file extensions  →  pattern rule fragment
    """
    if re.match(r'^[A-Z][A-Z0-9_]+$', target):   # e.g. BACKGROUND_IMAGE, SED, COMMA
        return True
    if '/' in target or target.startswith('.'):
        return True
    return False


def parse_makefile(path, project_name=None):
    targets = {}
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return targets

    skip_set = set(GLOBAL_SKIP)
    if project_name and project_name in PROJECT_SKIP:
        skip_set |= PROJECT_SKIP[project_name]

    # Collect .PHONY declarations
    phony = set()
    for m in re.finditer(r'^\.PHONY\s*:\s*(.+)$', content, re.MULTILINE):
        for t in m.group(1).split():
            phony.add(t.strip())

    # Collect explicit target definitions  (name:)
    for m in re.finditer(r'^([a-zA-Z][a-zA-Z0-9_.-]*)\s*:', content, re.MULTILINE):
        target = m.group(1)
        if target not in targets:
            targets[target] = []

    # Add PHONY targets even if not explicitly defined with commands
    for t in phony:
        if t not in targets:
            targets[t] = []

    # Parse recipe lines for each target
    lines = content.split('\n')
    current_target = None
    for line in lines:
        m = re.match(r'^([a-zA-Z][a-zA-Z0-9_.-]*)\s*:', line)
        if m:
            current_target = m.group(1)
            if current_target not in targets:
                targets[current_target] = []
        elif line.startswith('\t') and current_target:
            cmd = line.strip()
            if cmd and not cmd.startswith('#'):
                targets[current_target].append(cmd)

    # Filter out fake / skipped targets
    filtered = {}
    for t, cmds in targets.items():
        if t in skip_set:
            continue
        if _is_fake_target(t):
            continue
        filtered[t] = cmds

    return filtered


def parse_tox(path):
    """
    Return the list of tox environments to attest.
    Handles:
      - [testenv:name] sections
      - envlist = py38,py39  or  py{38,39,310,311}-django{32,40}
    """
    envs = set()
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return []

    # Named sections
    for m in re.finditer(r'^\[testenv:([^\]]+)\]', content, re.MULTILINE):
        envs.add(m.group(1).strip())

    # envlist lines (may be multi-line with \ continuation)
    envlist_block = re.search(
        r'^envlist\s*=\s*(.+?)(?=^\S|\Z)', content,
        re.MULTILINE | re.DOTALL
    )
    if envlist_block:
        raw = envlist_block.group(1)
        # strip comments and continuation backslashes
        raw = re.sub(r'#[^\n]*', '', raw)
        raw = raw.replace('\\\n', ' ')
        tokens = re.split(r'[\s,]+', raw)
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            for expanded in _expand_brace(token):
                if expanded:
                    envs.add(expanded)

    return sorted(envs)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: parse_makefile.py <Makefile|tox.ini> [project_name]",
              file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    project_name = sys.argv[2] if len(sys.argv) > 2 else None

    if path.endswith('tox.ini'):
        result = parse_tox(path)
        print(json.dumps(result, indent=2))
    else:
        result = parse_makefile(path, project_name)
        print(json.dumps(result, indent=2))
