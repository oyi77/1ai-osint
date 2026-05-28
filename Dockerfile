# Multi-stage build for 1ai-osint
# Stage 1: Build OSINT tool binaries (GitHound)
FROM golang:1.22-bookworm AS tools-builder

RUN go install github.com/zricethezav/githound@latest && \
    go install github.com/gitleaks/gitleaks/v8@latest

# Stage 2: Python dependencies
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[dev]"

# Stage 3: Runtime
FROM python:3.12-slim AS runtime

# Install system dependencies required by OSINT tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    chromium \
    chromium-driver \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Install Sherlock and Maigret (social media OSINT)
RUN pip install --no-cache-dir sherlock-project maigret

# Copy Go-built binaries (GitHound + Gitleaks)
COPY --from=tools-builder /go/bin/githound /usr/local/bin/githound
COPY --from=tools-builder /go/bin/gitleaks /usr/local/bin/gitleaks

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

# Copy application code
COPY src/ src/
COPY pyproject.toml .

# Create non-root user and cache directory
RUN useradd --create-home --shell /bin/bash osint && \
    mkdir -p /app/.osint_cache && \
    chown -R osint:osint /app

USER osint

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--help"]
