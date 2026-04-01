# sbomit-generator-server

Attestation storage and enriched SPDX 2.3 SBOM generator.

Receives signed witness attestations, enriches them with syft package scans,
and exposes a GUAC collector endpoint for ingestion into the supply chain graph.

## Changes

1. **Syft as subprocess** — syft is called directly via `subprocess.Popen`
   with the right params (`syft <dir> -o spdx-json`), decoupled from sbomit.
2. **GUAC collector** — `GET /guac/collect` exposes all stored attestations
   as in-toto DSSE envelopes for GUAC to poll and ingest.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/attestations` | Upload a witness attestation JSON |
| GET | `/attestations` | List stored attestations |
| GET | `/sbom?format=spdx&catalog=syft&project_dir=/path` | Generate enriched SPDX 2.3 SBOM |
| GET | `/guac/collect` | GUAC collector — returns all attestations |
| GET | `/guac/collect?since=2026-03-31T00:00:00Z` | Filter by timestamp |
| GET | `/health` | Health check |

All endpoints require: `Authorization: Bearer <APTOKEN>`

## Run locally (Docker)

```bash
# Build and start
docker compose up --build

# Test
curl http://localhost:5000/health \
  -H "Authorization: Bearer sbomit-dev-token"
```

## Run on GCP VM

```bash
# SSH into your GCP VM
gcloud compute ssh sbomit-server

# Clone the repo
git clone https://github.com/<org>/sbomit-generator-server
cd sbomit-generator-server

# Set your token
export APTOKEN="your-secure-token-here"

# Start
docker compose up -d

# Check it's running
curl http://localhost:5000/health \
  -H "Authorization: Bearer your-secure-token-here"
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APTOKEN` | `sbomit-dev-token` | Auth token |
| `PORT` | `5000` | Port to listen on |
| `STORAGE_DIR` | `attestation_store` | Where attestations are stored |
| `SBOMIT_EXE` | auto-detected | Path to sbomit binary |
| `SYFT_EXE` | auto-detected | Path to syft binary |

## GUAC integration

GUAC polls `GET /guac/collect` to pick up new attestations:

```bash
# GUAC collector config points to:
http://<server-ip>:5000/guac/collect

# With auth header:
Authorization: Bearer <APTOKEN>

# Only fetch attestations since last poll:
GET /guac/collect?since=2026-03-31T12:00:00Z
```
