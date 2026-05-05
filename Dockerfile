FROM python:3.11-slim

LABEL maintainer="sbomit"
LABEL description="sbomit-generator-server — attestation storage + SPDX SBOM generator"

# Install syft
RUN apt-get update && apt-get install -y curl && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server
COPY server.py .

# Attestation store (mounted as volume on GCP)
RUN mkdir -p /app/attestation_store

ENV STORAGE_DIR=/app/attestation_store
ENV PORT=5000
ENV APTOKEN=sbomit-dev-token

EXPOSE 5000

CMD ["python", "server.py"]
