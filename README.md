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
2. Pre-warms the Go module cache
3. Runs witness on each build target, signing attestations with an ED25519 key
4. Uploads attestation JSON to sbomit-server
5. Generates enriched SBOM in SPDX 2.3, CycloneDX 1.5, and SPDX 2.2

---

## Files in This Repo

### `run_pipeline.py`
Unified Python runner — replaces the previous run_pipeline.sh + parse_makefile.py split.
- Detects build system: Makefile → tox.ini → go.mod
- Parses Makefile targets, filters fake ALL_CAPS variable definitions
- Expands tox brace syntax (py{38,39,310,311} → individual envs)
- Pre-warms Go module cache before attestation
- Runs witness on each target with selective --trace (fast steps only)
- Per-project skip sets (kyverno, argocd, flux2)
- Prints attestor timing after each step (environment, material, command-run, product)

### `disambiguate.py`
Cross-references witness --trace attestation with SBOM packages. Requires a Deep run first.

```bash
# Witness trace vs syft SBOM
python3 disambiguate.py --project gittuf

# Add sbomit vs syft delta (--compare-catalogs)
python3 disambiguate.py --project gittuf --compare-catalogs

# Output formats
python3 disambiguate.py --project gittuf --format json --output report.json
python3 disambiguate.py --project gittuf --format csv  --output report.csv
```

Parses attestations by type (material vs command-run vs product) with timestamps.
Shows which processes opened which modules, attestor durations, and multi-version conflicts.

**sbomit vs syft delta on gittuf:**
- sbomit: 443 packages, 442/443 with SHA256 checksums, all with primaryPackagePurpose: LIBRARY
- syft: 231 packages, 0 checksums, all UNSET
- sbomit finds golang.org/toolchain; syft over-reports 11 Windows/test packages

### `server.py`
Flask API running on the server VM (Docker). New endpoints added:
- `GET /status` — current project, processing state, attestation count, timing
- `POST /complete` — called by worker after SBOM generation
- `GET /attestations/<filename>` — individual attestation detail
- `POST /attestations/clear` — now accepts `{"project": "name"}` to track current run

### `pipeline_api.py`
Flask API on the worker VM. New features:
- Passes project name to server on clear so server tracks which project is processing
- Calls POST /complete after SBOM generation
- Proxy routes for server dashboard: /server-status, /server-attestations, /server-sbom, /guac-collect

---

## Web UI

### Worker page — http://localhost:8080
5-step flow: select project → choose run mode → preview command → live attestation log → SBOM result with attestor timing table.

Three run modes:
- **Quick** — attests fmt only, seconds
- **Full** — attests build, test, install, fmt (~15-20 min)
- **Deep** — same as full with --trace on build for disambiguation analysis

### Server dashboard — http://localhost:8080/server-dashboard
Shows server state in real time:
- Status banner: orange spinner while processing, green with download buttons when complete
- Attestation store: list of received files, expandable to show attestor timestamps
- Clear store button for manual cleanup

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

---

## Server API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/attestations` | Upload witness attestation JSON |
| POST | `/attestations/clear` | Clear store (accepts `{"project": "name"}`) |
| GET | `/attestations` | List stored attestations |
| GET | `/attestations/<filename>` | Get individual attestation |
| GET | `/sbom?format=spdx&catalog=syft&project_dir=/path` | Generate enriched SBOM |
| GET | `/status` | Current run status and timing |
| POST | `/complete` | Signal run completion with package count |
| GET | `/guac/collect` | GUAC collector endpoint |
| GET | `/health` | Health check |

All endpoints require: `Authorization: Bearer <APTOKEN>`

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APTOKEN` | `sbomit-dev-token` | Auth token |
| `PORT` | `5000` | Port to listen on |
| `STORAGE_DIR` | `attestation_store` | Attestation storage path |
| `SYFT_EXE` | auto-detected | Path to syft binary |
