# Installing sbomit-init

All methods accept the same options. Choose what fits your workflow.

## GitHub CLI (recommended)

    gh extension install sbomit/gh-sbomit
    gh sbomit init

## Homebrew (macOS / Linux)

    brew tap sbomit/sbomit
    brew install sbomit-init
    sbomit-init

## npx (Node.js)

    npx sbomit-init

## pipx (Python)

    pipx run sbomit-init

## Direct download with checksum verification

    curl -sSL https://sbomit.dev/install.sh -o sbomit-init.sh
    curl -sSL https://sbomit.dev/checksums.txt -o checksums.txt
    sha256sum --check --ignore-missing checksums.txt
    bash sbomit-init.sh

## Options

    sbomit-init --help
    sbomit-init --server https://my-sbomit-server.com
    sbomit-init --no-pr
    sbomit-init --repo-dir /path/to/repo
