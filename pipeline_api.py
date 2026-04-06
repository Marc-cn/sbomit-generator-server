#!/usr/bin/env python3
"""
Pipeline API — runs on sbomit-worker (port 8081)
Receives requests from the webpage, runs witness attestation,
uploads to sbomit-server, and streams logs back via SSE.

Improvements over previous version:
  - Per-project skip target overrides (kyverno install-tools etc.)
  - All 3 SBOM formats fetched in parallel (ThreadPoolExecutor)
  - Attestation uploads run concurrently
  - go mod download pre-warm handled in run_pipeline.sh
"""
import subprocess, os, json, threading, concurrent.futures
from flask import Flask, Response, request, jsonify, send_from_directory

app = Flask(__name__)

SBOMIT_DIR = os.path.expanduser("~/SBOMIT")
SERVER_URL  = "http://10.10.20.2:5000"
API_TOKEN   = "sbomit-dev-token"

# ── Base skip lists ──────────────────────────────────────────────────────────
SKIP_TARGETS_QUICK = "just-install,generate,default,build,test,install"
SKIP_TARGETS_FULL  = "just-install,generate,default"

# ── Per-project extra skips (appended to whichever base list is used) ────────
SKIP_TARGETS_PROJECT = {
    "kyverno": [
        "install-tools",   # downloads entire k8s toolchain — 40+ min
        "build-images",    # requires Docker daemon
        "ko-build",        # requires ko + registry auth
        "kind-create-cluster",
        "kind-delete-cluster",
        "deploy",
    ],
}

PROJECTS = {
    "gittuf":  os.path.expanduser("~/projects/gittuf"),
    "tuf":     os.path.expanduser("~/projects/tuf"),
    "intoto":  os.path.expanduser("~/projects/intoto"),
    "sbomit":  os.path.expanduser("~/projects/sbomit"),
    "kyverno": os.path.expanduser("~/projects/kyverno"),
}


def get_skip_targets(project, mode):
    """Return the final comma-separated skip string for a project+mode combo."""
    base = SKIP_TARGETS_FULL if mode == "full" else SKIP_TARGETS_QUICK
    extra = SKIP_TARGETS_PROJECT.get(project, [])
    if extra:
        return base + "," + ",".join(extra)
    return base


def upload_attestation(fpath, fname):
    """Upload a single attestation file; returns (fname, uid_or_None, ok)."""
    result = subprocess.run([
        "curl", "-s", "-X", "POST",
        f"{SERVER_URL}/attestations",
        "-H", f"Authorization: Bearer {API_TOKEN}",
        "-H", "Content-Type: application/json",
        "-d", f"@{fpath}"
    ], capture_output=True, text=True)
    try:
        resp = json.loads(result.stdout)
        uid = resp.get("saved", ["?"])[0][:8]
        return fname, uid, True
    except Exception:
        return fname, None, True


def fetch_sbom_format(fmt, project_dir, out_path):
    """Fetch one SBOM format from the server; returns (fmt, http_code)."""
    r = subprocess.run([
        "curl", "-s",
        f"{SERVER_URL}/sbom?format={fmt}&catalog=syft&project_dir={project_dir}",
        "-H", f"Authorization: Bearer {API_TOKEN}",
        "-o", out_path, "-w", "%{http_code}"
    ], capture_output=True, text=True)
    return fmt, r.stdout.strip()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("/var/www/sbomit", "index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "worker": "sbomit-worker"})


@app.route("/server-health")
def server_health():
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{SERVER_URL}/health",
            headers={"Authorization": f"Bearer {API_TOKEN}"}
        )
        urllib.request.urlopen(req, timeout=3)
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"status": "error"}), 503


@app.route("/run/<project>")
@app.route("/run/<project>/<mode>")
def run_pipeline(project, mode="quick"):
    if project not in PROJECTS:
        return jsonify({"error": f"Unknown project: {project}"}), 400

    def generate():
        skip = get_skip_targets(project, mode)
        yield f"data: Starting {mode} pipeline for {project}\n\n"
        if project in SKIP_TARGETS_PROJECT:
            skipped = ", ".join(SKIP_TARGETS_PROJECT[project])
            yield f"data: Project-specific skips: {skipped}\n\n"

        # ── Step 1: witness attestation ──────────────────────────────────────
        yield f"data: [1/3] Running witness attestation...\n\n"
        cmd = [
            "bash", f"{SBOMIT_DIR}/run_pipeline.sh",
            "--project-dir", f"projects/{project}",
            "--skip-targets", skip
        ]
        proc = subprocess.Popen(
            cmd, cwd=SBOMIT_DIR,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                yield f"data: {line}\n\n"
        proc.wait()

        # ── Clear server store ───────────────────────────────────────────────
        subprocess.run([
            "curl", "-s", "-X", "POST",
            f"{SERVER_URL}/attestations/clear",
            "-H", f"Authorization: Bearer {API_TOKEN}"
        ], capture_output=True)

        # ── Step 2: upload attestations (parallel) ───────────────────────────
        yield f"data: [2/3] Uploading attestations to server...\n\n"
        attest_dir = os.path.join(SBOMIT_DIR, "attestations", project)
        count = 0

        if os.path.isdir(attest_dir):
            files = [(os.path.join(attest_dir, f), f)
                     for f in sorted(os.listdir(attest_dir))
                     if f.endswith(".json")]

            # Upload up to 4 attestations concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futures = {ex.submit(upload_attestation, fp, fn): fn
                           for fp, fn in files}
                for future in concurrent.futures.as_completed(futures):
                    fname, uid, ok = future.result()
                    if uid:
                        yield f"data:   uploaded {fname} → {uid}...\n\n"
                    else:
                        yield f"data:   uploaded {fname}\n\n"
                    count += 1

        yield f"data: {count} attestation(s) uploaded\n\n"

        # ── Step 3: generate all 3 SBOM formats (parallel) ──────────────────
        yield f"data: [3/3] Generating enriched SBOM (syft scanning...).\n\n"
        project_dir = PROJECTS[project]
        os.makedirs(f"{SBOMIT_DIR}/sboms", exist_ok=True)

        formats = [
            ("spdx",      f"{SBOMIT_DIR}/sboms/sbom-{project}-rich.spdx.json"),
            ("cyclonedx", f"{SBOMIT_DIR}/sboms/sbom-{project}-rich.cdx.json"),
            ("spdx22",    f"{SBOMIT_DIR}/sboms/sbom-{project}-rich.spdx22.json"),
        ]

        pkgs = 0
        sources = 0
        results = {}

        # Fetch all 3 formats concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(fetch_sbom_format, fmt, project_dir, out): fmt
                       for fmt, out in formats}
            for future in concurrent.futures.as_completed(futures):
                fmt, code = future.result()
                results[fmt] = code

        # Report results and parse the spdx one for stats
        for fmt, out_path in formats:
            code = results.get(fmt, "?")
            if code == "200" and fmt == "spdx":
                try:
                    with open(out_path) as ff:
                        data = json.load(ff)
                    pkgs    = len(data.get("packages", []))
                    sources = len(data.get("attestationSources", []))
                except Exception:
                    pass
            yield f"data: format {fmt}: {'ok' if code == '200' else 'error ' + code}\n\n"

        yield f"data: SBOM generated: {pkgs} packages, {sources} attestation sources\n\n"
        yield f"data: DONE:{project}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/sbom/<project>")
def get_sbom(project):
    fmt = request.args.get("format", "spdx")
    fmt_map = {
        "spdx":      f"sbom-{project}-rich.spdx.json",
        "cyclonedx": f"sbom-{project}-rich.cdx.json",
        "spdx22":    f"sbom-{project}-rich.spdx22.json",
    }
    fname    = fmt_map.get(fmt, f"sbom-{project}-rich.spdx.json")
    sbom_path = os.path.join(SBOMIT_DIR, "sboms", fname)
    if not os.path.exists(sbom_path):
        return jsonify({"error": "SBOM not found"}), 404
    with open(sbom_path) as f:
        data = json.load(f)
    version = data.get("spdxVersion") or data.get("specVersion") or "unknown"
    return jsonify({
        "project":      project,
        "format":       fmt,
        "packages":     len(data.get("packages", []) or data.get("components", [])),
        "attestations": len(data.get("attestationSources", [])),
        "spdxVersion":  version,
        "name":         data.get("name", project),
        "sbom":         data
    })


if __name__ == "__main__":
    os.makedirs(os.path.expanduser("~/SBOMIT/sboms"), exist_ok=True)
    app.run(host="0.0.0.0", port=8081, debug=False)
