# gh-sbomit

GitHub CLI extension to add the SBOMit attestation pipeline to your project.

## Install

    gh extension install sbomit/gh-sbomit

## Usage

    gh sbomit init
    gh sbomit init --server https://my-server.com --no-pr

## What it does

1. Detects your build system (Go, Rust, Python, Node, Make)
2. Generates .github/workflows/sbomit.yml
3. Configures GitHub OIDC (no secrets needed)
4. Opens a PR with the changes
