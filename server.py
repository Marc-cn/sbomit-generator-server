#!/usr/bin/env python3
"""
sbomit-generator-server  —  server.py
LF Attestation-to-SBOM Server

Changes from Santiago Torres-Arias:
  1. Syft integrated as a clean subprocess (popen) — no longer called
     indirectly through sbomit flags. Syft runs independently, its SPDX
     output is merged with attestation data server-side.
  2. GET /guac/collect — GUAC collector endpoint. GUAC polls this route
     and picks up all stored attestations in in-toto envelope format.

Endpoints:
  POST /attestations                          — upload witness attestation JSON
  GET  /attestations                          — list stored attestations
  GET  /sbom?format=spdx&catalog=syft
            &project_dir=/path/to/project    — generate enriched SPDX 2.3 SBOM
  GET  /guac/collect                          — GUAC collector (polls for new attestations)
  GET  /health                                — health check

Auth: Authorization: Bearer <APTOKEN env var>
"""

import os
import json
import uuid
import shutil
import subprocess
import datetime
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG  —  all tunable via environment variables
# ─────────────────────────────────────────────────────────────────────────────

APTOKEN     = os.environ.get("APTOKEN", "sbomit-dev-token")
STORAGE_DIR = os.environ.get("STORAGE_DIR", "attestation_store")
SBOMIT_EXE  = os.environ.get("SBOMIT_EXE", shutil.which("sbomit") or "/usr/local/bin/sbomit")
PORT        = int(os.environ.get("PORT", 5000))

os.makedirs(STORAGE_DIR, exist_ok=True)

# Detect syft once at startup — Santiago: wire as subprocess with right params
SYFT_EXE = (
    os.environ.get("SYFT_EXE")
    or shutil.which("syft")
    or shutil.which("syft.exe")
)

FORMAT_MAP = {
    "spdx":      "spdx23",
    "spdx23":    "spdx23",
    "spdx22":    "spdx22",
    "cyclonedx": "cdx15",
    "cdx15":     "cdx15",
    "cdx14":     "cdx14",
}

# ─────────────────────────────────────────────────────────────────────────────
# AUTH HELPER
# ─────────────────────────────────────────────────────────────────────────────

def check_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth.split(" ", 1)[1] == APTOKEN


# ─────────────────────────────────────────────────────────────────────────────
# SANTIAGO CHANGE 1 — syft as a clean subprocess
#
# Instead of passing --catalog syft flags through sbomit, we call syft
# directly with popen and the right output params, then parse its SPDX JSON
# output ourselves. This decouples syft from sbomit completely.
# ─────────────────────────────────────────────────────────────────────────────

def run_syft(project_dir):
    """
    Run syft against project_dir as a subprocess.
    Returns the parsed SPDX JSON dict, or None on failure.

    Equivalent to:
      syft <project_dir> -o spdx-json
    """
    if not SYFT_EXE:
        return None, "syft not found in PATH"

    cmd = [SYFT_EXE, project_dir, "-o", "spdx-json"]
    print(f"  [syft] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
    except subprocess.TimeoutExpired:
        return None, "syft timed out after 120s"
    except FileNotFoundError:
        return None, f"syft binary not found at {SYFT_EXE}"

    if result.returncode != 0:
        return None, f"syft exited {result.returncode}: {result.stderr.strip()}"

    try:
        data = json.loads(result.stdout)
        packages = data.get("packages", [])
        print(f"  [syft] Found {len(packages)} packages in {project_dir}")
        return packages, None
    except json.JSONDecodeError as e:
        return None, f"syft output not valid JSON: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    attestation_files = [
        f for f in os.listdir(STORAGE_DIR)
        if f.endswith(".json") and not f.endswith(".sbom.json")
    ]
    return jsonify({
        "status":              "ok",
        "server":              "sbomit-generator-server v0.3",
        "stored_attestations": len(attestation_files),
        "sbomit_exe":          SBOMIT_EXE,
        "sbomit_found":        os.path.exists(SBOMIT_EXE) if SBOMIT_EXE else False,
        "syft_exe":            SYFT_EXE or "not found",
        "syft_found":          SYFT_EXE is not None,
        "storage_dir":         STORAGE_DIR,
    })



# ── Runtime state — current project being processed ──────────────────────────
_current_project = {"name": None, "started": None, "attestation_count": 0}


@app.route("/complete", methods=["POST"])
def complete_run():
    global _current_project
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    _current_project["status"] = "complete"
    _current_project["completed"] = datetime.datetime.utcnow().isoformat() + "Z"
    _current_project["packages"] = data.get("packages", 0)
    _current_project["attestations"] = data.get("attestations", 0)
    _current_project["formats"] = data.get("formats", [])
    _current_project["attestation_duration_s"] = data.get("attestation_duration_s", 0)
    return jsonify({"ok": True})

@app.route("/status", methods=["GET"])
def get_status():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    import glob
    files = glob.glob(os.path.join(STORAGE_DIR, "*.json"))
    return jsonify({
        "current_project":    _current_project.get("name"),
        "started":            _current_project.get("started"),
        "upload_completed":   _current_project.get("upload_completed"),
        "completed":          _current_project.get("completed"),
        "stored_attestations": len(files),
        "attestation_count":  len(files),
        "packages":           _current_project.get("packages", 0),
        "attestations":       _current_project.get("attestations", 0),
        "attestation_duration_s": _current_project.get("attestation_duration_s", 0),
        "status": _current_project.get("status", "processing") if _current_project.get("name") else "idle"
    })

@app.route("/attestations", methods=["POST"])
def upload_attestation():
    """Receive a witness attestation JSON file and store it."""
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    saved = []

    if request.is_json:
        data  = request.get_json()
        items = data if isinstance(data, list) else [data]
        for item in items:
            fname = f"{uuid.uuid4()}.json"
            fpath = os.path.join(STORAGE_DIR, fname)
            with open(fpath, "w") as f:
                json.dump(item, f, indent=2)
            saved.append(fname)

    elif request.files:
        for _, file in request.files.items():
            data  = json.loads(file.read())
            fname = f"{uuid.uuid4()}.json"
            fpath = os.path.join(STORAGE_DIR, fname)
            with open(fpath, "w") as f:
                json.dump(data, f, indent=2)
            saved.append(fname)

    else:
        return jsonify({"error": "Send a JSON body or multipart files"}), 400

    return jsonify({"saved": saved, "count": len(saved)}), 201



@app.route("/attestations/clear", methods=["POST"])
def clear_attestations():
    global _current_project
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    import glob
    files = glob.glob(os.path.join(STORAGE_DIR, "*.json"))
    for f in files:
        os.remove(f)
    # Accept optional project name to track current run
    data = request.get_json(silent=True) or {}
    project = data.get("project")
    if project:
        _current_project = {
            "name": project,
            "started": datetime.datetime.utcnow().isoformat() + "Z",
            "attestation_count": 0
        }
    else:
        _current_project = {"name": None, "started": None, "attestation_count": 0}
    return jsonify({"cleared": len(files), "project": project})


@app.route("/attestations/<filename>", methods=["GET"])
def get_attestation(filename):
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    import re
    if not re.match(r"^[a-f0-9\-]+\.json$", filename):
        return jsonify({"error": "Invalid filename"}), 400
    fpath = os.path.join(STORAGE_DIR, filename)
    if not os.path.exists(fpath):
        return jsonify({"error": "Not found"}), 404
    with open(fpath) as f:
        data = json.load(f)
    return jsonify(data)

@app.route("/attestations", methods=["GET"])
def list_attestations():
    """List all stored attestation files."""
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    files = sorted([
        f for f in os.listdir(STORAGE_DIR)
        if f.endswith(".json") and not f.endswith(".sbom.json")
    ])
    return jsonify({"attestations": files, "count": len(files)})


@app.route("/sbom", methods=["GET"])
def generate_sbom():
    """
    Generate an enriched SPDX 2.3 SBOM by:
      1. Running syft as a subprocess against project_dir (Santiago change 1)
      2. Loading all stored witness attestations
      3. Merging both into one SPDX 2.3 document
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    fmt_param  = request.args.get("format", "spdx").lower()
    sbomit_fmt = FORMAT_MAP.get(fmt_param)
    if not sbomit_fmt:
        return jsonify({
            "error": f"Unknown format '{fmt_param}'",
            "valid": list(FORMAT_MAP.keys())
        }), 400

    use_catalog = request.args.get("catalog", "").lower()
    project_dir = request.args.get("project_dir", "")

    # Validate syft params
    syft_packages = []
    syft_error    = None

    if use_catalog == "syft":
        if not project_dir:
            return jsonify({
                "error": "catalog=syft requires project_dir query parameter"
            }), 400
        if not os.path.isdir(project_dir):
            return jsonify({
                "error": f"project_dir not found: {project_dir}"
            }), 400

        # Santiago change 1: call syft as a clean subprocess
        syft_packages, syft_error = run_syft(project_dir)
        if syft_error:
            print(f"  [syft] Warning: {syft_error}")

    # Load stored attestations
    attestation_files = sorted([
        f for f in os.listdir(STORAGE_DIR)
        if f.endswith(".json") and not f.endswith(".sbom.json")
    ])
    if not attestation_files:
        return jsonify({
            "error": "No attestations stored yet. POST some first."
        }), 404

    # Use syft packages directly + attestation files as sources
    all_packages    = list(syft_packages or [])
    processed_files = list(attestation_files)
    errors          = []

    # Deduplicate packages by (name, version) and enrich missing fields
    seen = set()
    deduped = []
    for p in all_packages:
        key = (p.get("name", ""), p.get("versionInfo", "") or p.get("version", ""))
        if key not in seen:
            seen.add(key)
            # Fix downloadLocation — derive from purl for Go modules
            if not p.get("downloadLocation") or p.get("downloadLocation") == "NOASSERTION":
                purl = next((r.get("referenceLocator","") for r in p.get("externalRefs",[]) if r.get("referenceType")=="purl"), "")
                if purl.startswith("pkg:golang/"):
                    mod = purl.replace("pkg:golang/","").split("@")[0]
                    ver = purl.split("@")[1] if "@" in purl else ""
                    p["downloadLocation"] = f"https://pkg.go.dev/{mod}@{ver}" if ver else f"https://pkg.go.dev/{mod}"
                elif purl.startswith("pkg:pypi/"):
                    name = purl.replace("pkg:pypi/","").split("@")[0]
                    p["downloadLocation"] = f"https://pypi.org/project/{name}/"
                else:
                    p["downloadLocation"] = "NOASSERTION"
            # Fix primaryPackagePurpose
            if not p.get("primaryPackagePurpose") or p.get("primaryPackagePurpose") == "UNSET":
                purl = next((r.get("referenceLocator","") for r in p.get("externalRefs",[]) if r.get("referenceType")=="purl"), "")
                if any(purl.startswith(f"pkg:{t}/") for t in ["golang","pypi","npm","maven","cargo","nuget"]):
                    p["primaryPackagePurpose"] = "LIBRARY"
                else:
                    p["primaryPackagePurpose"] = "OTHER"
            deduped.append(p)

    # Build merged document — SPDX or CycloneDX
    now      = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_uuid = str(uuid.uuid4())
    if sbomit_fmt.startswith("cdx"):
        spec = "1.5" if sbomit_fmt == "cdx15" else "1.4"
        merged = {
            "bomFormat":    "CycloneDX",
            "specVersion":  spec,
            "serialNumber": f"urn:uuid:{doc_uuid}",
            "version":      1,
            "metadata": {"timestamp": now, "tools": [{"name": "sbomit-generator-server", "version": "0.3"}, {"name": "syft"}]},
            "components": [{"type": "library", "name": p.get("name",""), "version": p.get("versionInfo","") or p.get("version",""), "purl": next((r.get("referenceLocator","") for r in p.get("externalRefs",[]) if r.get("referenceType")=="purl"), "")} for p in deduped if p.get("name")],
            "attestationSources": processed_files,
        }
        out_filename = f"sbom.cyclonedx{spec.replace('.','')}.json"
    else:
        merged = {
            "SPDXID":       "SPDXRef-DOCUMENT",
            "spdxVersion":  "SPDX-2.3" if sbomit_fmt == "spdx23" else "SPDX-2.2",
            "creationInfo": {"created": now, "creators": ["Tool: sbomit-generator-server v0.3", "Tool: syft"]},
            "name":              "sbomit-lf-server-merged",
            "dataLicense":       "CC0-1.0",
            "documentNamespace": f"https://sbomit.dev/sbom/{doc_uuid}",
            "packages":          deduped,
            "relationships":     [
                {
                    "spdxElementId":      "SPDXRef-DOCUMENT",
                    "relationshipType":   "DESCRIBES",
                    "relatedSpdxElement": deduped[0]["SPDXID"] if deduped else "SPDXRef-DOCUMENT"
                }
            ] + [
                {
                    "spdxElementId":      "SPDXRef-DOCUMENT",
                    "relationshipType":   "DESCRIBES",
                    "relatedSpdxElement": p["SPDXID"]
                }
                for p in deduped[1:] if p.get("SPDXID")
            ],
            "attestationSources": processed_files,
            "catalogMode":       f"syft ({project_dir})" if use_catalog == "syft" else "file-hash-only",
        }
        out_filename = "sbom.spdx23.json" if sbomit_fmt == "spdx23" else "sbom.spdx22.json"
    if errors: merged["warnings"] = errors
    if syft_error: merged["syftWarning"] = syft_error
    print(f"  [sbom] Generated: {len(deduped)} packages, {len(processed_files)} attestations, fmt={sbomit_fmt}")
    return Response(
        json.dumps(merged, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={out_filename}"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# SANTIAGO CHANGE 2 — GUAC collector endpoint
#
# GUAC (Graph for Understanding Artifact Composition) has a concept of
# "collectors" — small hold locations it polls periodically to pick up
# new attestations. This endpoint exposes all stored attestations in
# in-toto DSSE envelope format so GUAC can ingest them automatically.
#
# GUAC polls GET /guac/collect, reads what's there, and ingests it.
# No push required from our side — GUAC does the work.
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/guac/collect", methods=["GET"])
def guac_collect():
    """
    GUAC collector endpoint.

    Returns all stored attestations as a JSON array of in-toto DSSE envelopes.
    GUAC polls this endpoint and ingests whatever it finds.

    Optional query params:
      ?since=<ISO8601>   — only return attestations newer than this timestamp
      ?limit=<int>       — max number of attestations to return (default: all)
    """
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    since_str = request.args.get("since")
    limit     = request.args.get("limit", type=int)

    # Parse ?since filter
    since_dt = None
    if since_str:
        try:
            since_dt = datetime.datetime.fromisoformat(since_str.replace("Z", "+00:00"))
        except ValueError:
            return jsonify({
                "error": f"Invalid 'since' timestamp: {since_str}",
                "hint":  "Use ISO 8601 format e.g. 2026-03-31T00:00:00Z"
            }), 400

    # Load attestation files
    attestation_files = sorted([
        f for f in os.listdir(STORAGE_DIR)
        if f.endswith(".json") and not f.endswith(".sbom.json")
    ])

    envelopes = []
    for fname in attestation_files:
        fpath = os.path.join(STORAGE_DIR, fname)

        # Apply ?since filter using file mtime
        if since_dt:
            mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(fpath),
                tz=datetime.timezone.utc
            )
            if mtime <= since_dt:
                continue

        try:
            with open(fpath) as f:
                envelope = json.load(f)
            envelopes.append({
                "id":       fname.replace(".json", ""),
                "filename": fname,
                "collected_at": datetime.datetime.fromtimestamp(
                    os.path.getmtime(fpath),
                    tz=datetime.timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "envelope": envelope,
            })
        except (json.JSONDecodeError, IOError) as e:
            print(f"  [guac] Warning: could not read {fname}: {e}")
            continue

    # Apply ?limit
    if limit:
        envelopes = envelopes[:limit]

    return jsonify({
        "collector":   "sbomit-generator-server",
        "version":     "0.3",
        "count":       len(envelopes),
        "attestations": envelopes,
    })


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n  sbomit-generator-server v0.3")
    print(f"  ─────────────────────────────────────")
    print(f"  Listening : http://0.0.0.0:{PORT}")
    print(f"  Token     : {APTOKEN}")
    print(f"  Storage   : {STORAGE_DIR}")
    print(f"  sbomit    : {SBOMIT_EXE}")
    print(f"  syft      : {SYFT_EXE or 'not found (optional)'}")
    print(f"")
    print(f"  Endpoints :")
    print(f"    POST /attestations              upload witness JSON")
    print(f"    GET  /attestations              list stored attestations")
    print(f"    GET  /sbom?format=spdx          generate SPDX 2.3 SBOM")
    print(f"         &catalog=syft              enrich with syft packages")
    print(f"         &project_dir=/path         project to scan")
    print(f"    GET  /guac/collect              GUAC collector endpoint")
    print(f"         ?since=<ISO8601>           filter by timestamp")
    print(f"    GET  /health                    health check")
    print(f"")
    app.run(host="0.0.0.0", port=PORT, debug=False)
