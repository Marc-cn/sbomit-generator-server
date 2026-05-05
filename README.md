# SBOMit Generator Server

SBOMit pipeline: witness --trace build attestation + syft + ptrace union SBOM generation.

## Key Files

- server.py: Flask server with ptrace union patch
- run_pipeline.py: witness deep pipeline per project
- evaluation/run_full_eval.py: full evaluation script
- evaluation/sbomit_full_evaluation.csv: final results
- evaluation/records/: per-project JSON records

## SBOMit SBOM = syft UNION ptrace-compiled packages

Results: SBOMit > Syft in 9/10 projects, SBOMit > Trivy in 10/10 projects.
Syft false positive rate: 15-83%. Syft miss rate: 5-56%.

## Infrastructure
- sbomit-worker: 10.10.20.3 (e2-medium, 78GB)
- sbomit-server: 10.10.20.2 (e2-micro, Docker)
- GCP: jc4946-sbomit-6903
- Tools: witness v0.10.1, syft 1.42.3, trivy 0.69.3
