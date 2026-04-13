# SBOMit Attestation Pipeline

Software supply chain attestation pipeline for the Linux Foundation SBOMit project.
Generates enriched SBOMs by combining witness attestations with syft package scans.

---

## What This Does

The pipeline runs on two GCP VMs:

- **sbomit-worker (VM1)** — runs witness attestation on each project, streams logs to the web UI
- **sbomit-server (VM2)** — stores attestations, runs syft, generates enriched SBOMs

For each supported project, the pipeline:
1. Detects the build system (Makefile, tox.ini, or go.mod)
2. Runs witness on each build target, signing attestations with an ED25519 key
3. Uploads attestation JSON to sbomit-server
4. Generates enriched SBOM in SPDX 2.3, CycloneDX 1.5, and SPDX 2.2

---

## Files in This Repo

### `run_pipeline.py`
Unified Python runner — replaces the previous run_pipeline.sh + parse_makefile.py split.
- Detects build system: Makefile → tox.ini → go.mod
- Parses Makefile targets, filters fake ALL_CAPS variable definitions
- Expands tox brace syntax (py{38,39,310,311} → individual envs)
- Calls make/tox directly — no bash -c wrapper (cleaner attestations)
- `--prewarm` flag — pre-warm Go module cache before attestation (default: off, so network activity is captured)
- `make -o test` override — prevents recursive test tracing during build steps
- Go build fallback — if Makefile has no build target, injects `go build ./...`
- Per-project skip sets (kyverno, argo-cd, flux2, protobom)
- Prints attestor timing after each step (environment, material, command-run, product)

```bash
python3 run_pipeline.py --project-dir projects/gittuf --mode quick
python3 run_pipeline.py --project-dir projects/gittuf --mode full
python3 run_pipeline.py --project-dir projects/gittuf --mode deep  # enables --trace for disambiguation
python3 run_pipeline.py --project-dir projects/gittuf --mode quick --prewarm  # pre-warm cache
```

### `disambiguate.py`
Disambiguates which packages were actually compiled into the binary vs declared but never used.
Runs sbomit generate twice and diffs the outputs. Requires a Deep run first.

```bash
python3 disambiguate.py --project gittuf
python3 disambiguate.py --project gittuf --format json --output report.json
python3 disambiguate.py --project gittuf --format csv  --output report.csv
```

**How it works:** runs sbomit alone (--trace syscall data) then sbomit --catalog syft (+ filesystem scan). The delta = packages syft reports that the compiler never opened.

**Results:**
- gittuf: 442 compiled, 94 syft-only (GitHub Actions CI packages)
- protobom: 48 compiled, 35 syft-only (linter tools, CI actions)

### `test_makefile_parser.py`
Automated validation tests for the Makefile parsing logic.

```bash
python3 test_makefile_parser.py
```

### `server.py`
Flask API running on the server VM (Docker). Endpoints:
- `POST /attestations` — upload witness attestation JSON
- `POST /attestations/clear` — clear store (accepts `{"project": "name"}`)
- `GET /attestations` — list stored attestations
- `GET /attestations/<filename>` — get individual attestation
- `GET /sbom?format=spdx&catalog=syft&project_dir=/path` — generate enriched SBOM
- `GET /status` — current run status, timing, package count
- `POST /complete` — signal run completion with package count
- `GET /guac/collect` — GUAC collector endpoint
- `GET /health` — health check

---

## Web UI

### Worker page — http://localhost:8080
5-step flow: select project → choose run mode → preview command → live attestation log → SBOM result with attestor timing table.

Three run modes:
- **Quick** — attests fmt only, seconds
- **Full** — attests build, test, install, fmt (~15-20 min)
- **Deep** — same as full with --trace on build for disambiguation analysis

### Server dashboard — http://localhost:8080/server-dashboard
Real-time server state:
- Status banner: orange spinner while processing, green with download buttons when complete
- Timing metrics: attestation generation time
- Attestation store: list of received files, expandable to show attestor timestamps
- Clear store button

---

## Supported Projects

| Project | Language | Build System | Packages | Attestations |
|---------|----------|-------------|----------|--------------|
| gittuf  | Go       | Makefile    | 249      | 4            |
| tuf     | Python   | tox.ini     | 16       | 5            |
| in-toto | Python   | tox.ini     | 23       | 5            |
| sbomit  | Go       | go.mod      | 16       | 3            |
| kyverno | Go       | Makefile    | 505      | 19           |
| flux2   | Go       | Makefile    | —        | 5            |
| argo-cd | Go       | Makefile    | —        | —            |
| protobom| Go       | Makefile    | 48       | 1            |

---

## Environment Variables (server.py)

| Variable | Default | Description |
|----------|---------|-------------|
| `APTOKEN` | `sbomit-dev-token` | Auth token |
| `PORT` | `5000` | Port to listen on |
| `STORAGE_DIR` | `attestation_store` | Attestation storage path |
| `SYFT_EXE` | auto-detected | Path to syft binary |
