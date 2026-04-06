# SBOMit Attestation Pipeline

Software supply chain attestation pipeline for the Linux Foundation SBOMit project.
Generates enriched SBOMs by combining witness attestations with syft package scans.

---

## What This Does

The pipeline runs on two GCP VMs:

- **sbomit-worker** — runs witness attestation on each project, streams logs to the web UI
- **sbomit-server** — stores attestations, runs syft, generates enriched SBOMs

For each supported project, the pipeline:
1. Detects the build system (Makefile, tox.ini, or go.mod)
2. Runs witness on each build target, signing attestations with an ED25519 key
3. Uploads attestation JSON to sbomit-server
4. Generates enriched SBOM in SPDX 2.3, CycloneDX 1.5, and SPDX 2.2

---

## Files in This Repo

### `pipeline_api.py`
Flask API running on the worker VM. Orchestrates the full pipeline:
- Receives run requests from the web UI via Server-Sent Events (SSE)
- Streams live logs to the browser
- Uploads attestations to the server concurrently
- Fetches all 3 SBOM formats in parallel
- Handles per-project skip overrides

### `run_pipeline.sh`
Witness attestation runner:
- Detects build system: Makefile → tox.ini → go.mod
- Pre-warms Go module cache before attestation
- Runs `witness run` on each target, signing with ED25519
- Applies `--trace` (ptrace) selectively — only for fast steps, disabled for `go test -race`

### `parse_makefile.py`
Build target parser:
- Parses Makefile `.PHONY` targets
- Filters fake ALL_CAPS variable definitions that are not real targets
- Expands tox brace syntax (`py{38,39,310,311}` → individual envs)
- Applies per-project skip sets

### `server.py`
Flask API running on the server VM (Docker):
- Receives and stores witness attestation JSON
- Runs syft on the project directory to scan packages
- Merges syft packages with attestation metadata into enriched SBOM
- Exposes GUAC collector endpoint for supply chain graph ingestion

---

## Supported Projects

| Project | Language | Build System | Packages | Attestations |
|---------|----------|-------------|----------|--------------|
| gittuf  | Go       | Makefile    | 249      | 4            |
| tuf     | Python   | tox.ini     | 16       | 5            |
| in-toto | Python   | tox.ini     | 23       | 5            |
| sbomit  | Go       | go.mod      | 16       | 3            |
| kyverno | Go       | Makefile    | 505      | 19           |

---

## Server API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/attestations` | Upload witness attestation JSON |
| POST | `/attestations/clear` | Clear store before each run |
| GET | `/attestations` | List stored attestations |
| GET | `/sbom?format=spdx&catalog=syft&project_dir=/path` | Generate enriched SBOM |
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
