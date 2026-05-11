#!/usr/bin/env bash
# sbomit-init.sh — Add the SBOMit attestation pipeline to your project
#
# Usage:
#   bash sbomit-init.sh                          # run inside your repo
#   bash sbomit-init.sh --repo-dir /path/to/repo
#   bash sbomit-init.sh --server https://myserver.com --no-pr
#
# Requirements:
#   - git
#   - gh (GitHub CLI, https://cli.github.com)
#
# One-liner install:
#   curl -sSL https://raw.githubusercontent.com/sbomit/sbomit/main/install.sh | bash

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SBOMIT_SERVER="${SBOMIT_SERVER:-https://sbomit.dev}"
REPO_DIR="."
OPEN_PR=true
NO_SECRETS=false
BRANCH="sbomit/add-attestation-pipeline"

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'
info()    { echo -e "${GREEN}==>${NC} $*"; }
warn()    { echo -e "${YELLOW}WARN:${NC} $*"; }
error()   { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
success() { echo -e "${GREEN}${BOLD}✓${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --repo-dir)   REPO_DIR="$2";       shift 2 ;;
        --server)     SBOMIT_SERVER="$2";  shift 2 ;;
        --no-pr)      OPEN_PR=false;       shift   ;;
        --no-secrets) NO_SECRETS=true;     shift   ;;
        --token)      SBOMIT_TOKEN="$2";   shift 2 ;;
        --help|-h)
            echo "Usage: sbomit-init.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --repo-dir   <path>   Path to the git repository (default: .)"
            echo "  --server     <url>    SBOMit server URL (default: https://sbomit.dev)"
            echo "  --token      <token>  SBOMit bearer token (or set SBOMIT_TOKEN env var)"
            echo "  --no-pr               Commit directly, don't open a PR"
            echo "  --no-secrets          Skip setting GitHub secrets (set them manually)"
            echo "  --help                Show this help"
            exit 0 ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

cd "$REPO_DIR"
REPO_DIR=$(pwd)

echo ""
echo -e "${BOLD}SBOMit Pipeline Installer${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  repo:   $REPO_DIR"
echo "  server: $SBOMIT_SERVER"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────
info "Checking dependencies..."
for cmd in git gh curl; do
    if ! command -v "$cmd" &>/dev/null; then
        if [[ "$cmd" == "gh" ]]; then
            error "'gh' (GitHub CLI) is required.\n  Install: https://cli.github.com/\n  Then run: gh auth login"
        fi
        error "'$cmd' is required but not installed."
    fi
done

if ! git rev-parse --git-dir &>/dev/null; then
    error "Not a git repository: $REPO_DIR"
fi

if ! gh auth status &>/dev/null; then
    error "Not authenticated with GitHub CLI.\n  Run: gh auth login"
fi
success "Dependencies OK"

# ── Detect build system ───────────────────────────────────────────────────────
info "Detecting build system..."

detect_build_system() {
    if [[ -f "go.mod" ]];                                          then echo "go"
    elif [[ -f "Cargo.toml" ]];                                    then echo "rust"
    elif [[ -f "pyproject.toml" || -f "setup.py" ]];              then echo "python"
    elif [[ -f "package.json" ]];                                  then echo "node"
    elif [[ -f "Makefile" && $(grep -c "^build:" Makefile) -gt 0 ]]; then echo "make"
    else echo "unknown"
    fi
}

BUILD_SYSTEM=$(detect_build_system)

case "$BUILD_SYSTEM" in
    go)
        BUILD_CMD="go build ./..."
        SETUP_STEPS="      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true"
        ;;
    rust)
        BUILD_CMD="cargo build --release"
        SETUP_STEPS="      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: stable"
        ;;
    python)
        BUILD_CMD="pip install -e ."
        SETUP_STEPS="      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'
          cache: pip"
        ;;
    node)
        BUILD_CMD="npm ci && npm run build"
        SETUP_STEPS="      - name: Set up Node
        uses: actions/setup-node@v4
        with:
          node-version: lts/*
          cache: npm"
        ;;
    make)
        BUILD_CMD="make build"
        SETUP_STEPS=""
        ;;
    *)
        warn "Could not detect build system. Defaulting to 'make build'."
        warn "Edit .github/workflows/sbomit.yml to set the correct build command."
        BUILD_CMD="make build"
        SETUP_STEPS=""
        ;;
esac

success "Detected: $BUILD_SYSTEM → $BUILD_CMD"

# ── Detect default branch ─────────────────────────────────────────────────────
DEFAULT_BRANCH=$(git remote show origin 2>/dev/null | grep "HEAD branch" | awk '{print $NF}' || echo "main")
REPO_NAME=$(basename "$REPO_DIR")

# ── Generate workflow ─────────────────────────────────────────────────────────
info "Generating .github/workflows/sbomit.yml..."
mkdir -p .github/workflows

WORKFLOW=".github/workflows/sbomit.yml"

cat > "$WORKFLOW" << WORKFLOW_EOF
name: SBOMit Attestation

on:
  push:
    branches: [$DEFAULT_BRANCH]
  pull_request:

permissions:
  id-token: write  # needed for OIDC
  contents: write

jobs:
  sbomit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

$SETUP_STEPS

      - name: Install witness
        run: |
          curl -sSL https://raw.githubusercontent.com/in-toto/witness/main/install.sh | sh
          sudo mv witness /usr/local/bin/witness

      - name: Generate ephemeral signing key
        run: |
          openssl genpkey -algorithm ed25519 -out signing.key
          openssl pkey -in signing.key -pubout -out signing.pub

      - name: Attest build (ptrace + network-trace)
        run: |
          sudo witness run \\
            --trace \\
            --attestations "environment,git,material,product,network-trace" \\
            --signer-file-key-path signing.key \\
            --outfile attestation.json \\
            -- $BUILD_CMD

      - name: Upload attestation + generate SBOM
        run: |
          mkdir -p sbom
          curl -sSf -X POST "\${{ vars.SBOMIT_SERVER }}/generate?name=$REPO_NAME" \\
            -H "Authorization: Bearer \${{ secrets.SBOMIT_TOKEN }}" \\
            -H "Content-Type: application/json" \\
            --data-binary @attestation.json \\
            -o sbom/sbom.spdx.json
          echo "==> SBOM generated"
          python3 -c "
          import json, sys
          d = json.load(open('sbom/sbom.spdx.json'))
          pkgs = d.get('packages', [])
          purls = [r.get('referenceLocator') for p in pkgs for r in p.get('externalRefs', []) if r.get('referenceType') == 'purl']
          print(f'Packages: {len(pkgs)}  |  PURLs: {len(purls)}')
          " || true

      - name: Commit SBOM to repository
        if: github.event_name == 'push'
        run: |
          git config user.name  "sbomit-bot"
          git config user.email "sbomit-bot@users.noreply.github.com"
          git add sbom/sbom.spdx.json
          git diff --staged --quiet || git commit -m "chore: update SBOM [skip ci]"
          git push
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}

      - name: Upload SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-\${{ github.sha }}
          path: sbom/sbom.spdx.json
          retention-days: 90
WORKFLOW_EOF

success "Workflow written to $WORKFLOW"

# ── Create sbom directory with placeholder ────────────────────────────────────
mkdir -p sbom
if [[ ! -f "sbom/.gitkeep" && ! -f "sbom/sbom.spdx.json" ]]; then
    touch sbom/.gitkeep
fi

# ── Set GitHub secrets and variables ─────────────────────────────────────────
if [[ "$NO_SECRETS" == false ]]; then
    info "Setting GitHub repository secrets and variables..."

    # SBOMIT_TOKEN
    if [[ -n "${SBOMIT_TOKEN:-}" ]]; then
        echo "$SBOMIT_TOKEN" | gh secret set SBOMIT_TOKEN
        success "SBOMIT_TOKEN secret set from environment"
    else
        echo -n "  Enter SBOMIT_TOKEN (press Enter to skip): "
        read -rs TOKEN
        echo
        if [[ -n "$TOKEN" ]]; then
            echo "$TOKEN" | gh secret set SBOMIT_TOKEN
            success "SBOMIT_TOKEN secret set"
        else
            warn "SBOMIT_TOKEN skipped — set it manually in repo Settings → Secrets"
        fi
    fi

    # SBOMIT_SERVER as a variable (not secret — not sensitive)
    gh variable set SBOMIT_SERVER --body "$SBOMIT_SERVER"
    success "SBOMIT_SERVER variable set to $SBOMIT_SERVER"
fi

# ── Git commit ────────────────────────────────────────────────────────────────
info "Committing workflow..."
git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH"
git add .github/workflows/sbomit.yml sbom/
git commit -m "ci: add SBOMit attestation pipeline

Auto-generated by sbomit-init.sh
- Build system:  $BUILD_SYSTEM
- Build command: $BUILD_CMD
- SBOMit server: $SBOMIT_SERVER

On every push to $DEFAULT_BRANCH:
  1. witness runs with --trace + network-trace
  2. Attestation posted to SBOMit server
  3. SBOM committed to sbom/sbom.spdx.json
  4. SBOM attached as Actions artifact"

git push -u origin "$BRANCH"
success "Branch pushed: $BRANCH"

# ── Open PR ───────────────────────────────────────────────────────────────────
if [[ "$OPEN_PR" == true ]]; then
    info "Opening pull request..."
    PR_URL=$(gh pr create \
        --title "ci: add SBOMit attestation pipeline" \
        --body "## SBOMit Attestation Pipeline

This PR adds automated SBOM generation to the project using [SBOMit](https://sbomit.dev).

### How it works
1. On every push to \`$DEFAULT_BRANCH\`, \`witness\` runs with \`--trace\` (ptrace) and \`network-trace\`
2. The attestation is posted to the SBOMit server
3. The server generates an SPDX 2.3 SBOM from build evidence
4. The SBOM is committed to \`sbom/sbom.spdx.json\` and attached as an Actions artifact

### Build system detected
\`$BUILD_SYSTEM\` → \`\`\`$BUILD_CMD\`\`\`

### Secrets configured
| Name | Type | Value |
|------|------|-------|
| \`SBOMIT_TOKEN\` | Secret | *(set)* |
| \`SBOMIT_SERVER\` | Variable | \`$SBOMIT_SERVER\` |

### Review checklist
- [ ] Build command is correct for this project
- [ ] \`sbom/\` directory is acceptable in the repo
- [ ] SBOMit server is reachable from GitHub Actions runners" \
        --head "$BRANCH" \
        --base "$DEFAULT_BRANCH")
    success "PR opened: $PR_URL"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  SBOMit pipeline added successfully!${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Workflow:  .github/workflows/sbomit.yml"
echo "  SBOM dir:  sbom/sbom.spdx.json"
echo "  Branch:    $BRANCH"
[[ "$OPEN_PR" == true ]] && echo "  PR:        $PR_URL"
echo ""
echo "  Next steps:"
echo "  1. Review the PR and merge"
echo "  2. Make sure the SBOMit server is reachable from GitHub Actions"
echo "  3. Check the Actions tab after the first push"
echo ""
