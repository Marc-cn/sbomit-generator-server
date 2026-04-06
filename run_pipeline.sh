#!/bin/bash
# run_pipeline.sh — runs witness attestation for a project
# Uses parse_makefile.py for target detection (handles all Makefile formats)
# Uses the exact witness command syntax verified to work manually

PROJECT_DIR=""
SKIP_TARGETS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --project-dir)   PROJECT_DIR="$2"; shift 2 ;;
    --skip-targets)  SKIP_TARGETS="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$PROJECT_DIR" ]; then
  echo "Usage: $0 --project-dir <path> [--skip-targets \"t1,t2\"]"
  exit 1
fi

SBOMIT_DIR="$(cd "$(dirname "$0")" && pwd)"
WITNESS="$SBOMIT_DIR/witness/witness"
SIGNING_KEY="$SBOMIT_DIR/signing.key"
PARSE_MAKEFILE="$SBOMIT_DIR/parse_makefile.py"
PROJECT_NAME="$(basename $PROJECT_DIR)"
ATTESTATION_DIR="$SBOMIT_DIR/attestations/$PROJECT_NAME"

mkdir -p "$ATTESTATION_DIR"

# Build skip list array
IFS=',' read -ra SKIP_ARRAY <<< "$SKIP_TARGETS"

should_skip() {
  local target="$1"
  for skip in "${SKIP_ARRAY[@]}"; do
    skip="$(echo "$skip" | tr -d ' ')"
    if [ "$target" = "$skip" ]; then
      return 0
    fi
  done
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Attest one step — exact command verified to work manually:
#
#   ./witness/witness run \
#     --step <name> \
#     --signer-file-key-path signing.key \
#     --attestations "environment" \
#     -o attestations/<project>/<name>.json \
#     -- bash -c "<command>; true"
#
# The "; true" ensures witness writes the file even if the command fails.
# ─────────────────────────────────────────────────────────────────────────────

run_step() {
  local step_name="$1"
  local cmd="$2"
  local out_file="$ATTESTATION_DIR/${step_name}.json"

  if should_skip "$step_name"; then
    echo "SKIP: $step_name"
    return
  fi

  echo "ATTESTING: $step_name"

  "$WITNESS" run \
    --step "$step_name" \
    --signer-file-key-path "$SIGNING_KEY" \
    --attestations "environment" \
    -o "$out_file" \
    -- bash -c "$cmd; true"

  if [ -f "$out_file" ]; then
    echo "  OK: $step_name ($(du -h "$out_file" | cut -f1))"
  else
    echo "  FAIL: $step_name — output file not written"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Detect build system and run steps
# ─────────────────────────────────────────────────────────────────────────────

FULL_PROJECT_DIR="$SBOMIT_DIR/$PROJECT_DIR"
cd "$FULL_PROJECT_DIR"

if [ -f "Makefile" ]; then
  echo "Detected: Makefile"

  # Use parse_makefile.py which handles all formats including ".PHONY : target"
  TARGETS_JSON=$(python3 "$PARSE_MAKEFILE" "Makefile" 2>/dev/null)
  TARGETS=$(echo "$TARGETS_JSON" | python3 -c \
    "import json,sys; print('\n'.join(json.load(sys.stdin).keys()))" 2>/dev/null)

  if [ -z "$TARGETS" ]; then
    echo "ERROR: parse_makefile.py returned no targets"
    exit 1
  fi

  for target in $TARGETS; do
    run_step "$target" "make $target"
  done

elif [ -f "tox.ini" ]; then
  echo "Detected: tox.ini"
  ENVS=$(grep '^\[testenv:' tox.ini | sed 's/\[testenv://;s/\]//')
  ENVLIST=$(grep '^envlist' tox.ini | sed 's/envlist\s*=\s*//' | tr ',' '\n' | tr -d ' ')
  ALL_ENVS=$(echo -e "$ENVS\n$ENVLIST" | sort -u | grep -v '^$')
  for env in $ALL_ENVS; do
    run_step "$env" "tox -e $env"
  done
  if [ -z "$ALL_ENVS" ]; then
    run_step "tox" "tox"
  fi

elif [ -f "go.mod" ]; then
  echo "Detected: go.mod"
  run_step "go-build" "go build ./..."
  run_step "go-test"  "go test ./..."
  run_step "go-fmt"   "gofmt -l ."

elif [ -f "pyproject.toml" ]; then
  echo "Detected: pyproject.toml"
  run_step "python-build" "python3 -m build"

else
  echo "ERROR: No recognized build system found in $FULL_PROJECT_DIR"
  exit 1
fi

echo ""
echo "Done. Attestations saved to: $ATTESTATION_DIR"
