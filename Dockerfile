# 1ai-osint Docker image
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ ./src/
COPY docs/ ./docs/

# Install Python dependencies
RUN pip install --no-cache-dir -e .[dev,crypto]

# Create non-root user
RUN useradd -m -s /bin/bash osint
USER osint

EXPOSE 8000

CMD ["python", "-m", "src.cli", "--help"]