# Hardened multi-stage Dockerfile
# Passes Checkov CKV_DOCKER_2 (non-root user), CKV_DOCKER_3 (no sudo),
# CKV_DOCKER_7 (pinned base image tag), CKV_DOCKER_9 (no COPY --chown root)

# ── Stage 1: Build ────────────────────────────────────────────────────
FROM python:3.11.9-slim AS builder

# Pin to specific digest for reproducibility in regulated environments
# python:3.11.9-slim@sha256:<digest>

WORKDIR /build

# Copy only dependency files first — maximises layer cache hits
COPY requirements.txt .

# Install to a prefix directory — avoids polluting system Python
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────
FROM python:3.11.9-slim AS runtime

# Metadata labels
LABEL maintainer="akhil@akhiladarsh.com"
LABEL org.opencontainers.image.source="https://github.com/akhiladarsh/devsecops-aws-pipeline"
LABEL org.opencontainers.image.description="Hardened production runtime image"

# Install security updates only — keep image minimal
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Create non-root user — CKV_DOCKER_2 compliance
RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --no-create-home --shell /bin/false appuser

WORKDIR /app

# Copy application code
COPY --chown=appuser:appgroup app/ .

# Drop to non-root — mandatory for HIPAA/SOC2 workloads
USER appuser

# Expose non-privileged port (>1024)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# No shell in CMD — prevents shell injection
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8080", "app:application"]
