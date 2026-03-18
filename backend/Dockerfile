# Seraph AI Defense System - Backend Dockerfile
# ==============================================
# FastAPI backend with security tools and CCE Worker

FROM python:3.11-slim

LABEL maintainer="Seraph AI Team"
LABEL description="Seraph AI Defense System Backend"
LABEL version="5.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    gnupg \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libffi-dev \
    libssl-dev \
    git \
    # WireGuard tools
    wireguard-tools \
    iproute2 \
    iptables \
    openresolv \
    # Detection/forensics tooling
    suricata \
    yara \
    jq \
    # Network tools
    nmap \
    tcpdump \
    # Process tools
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy binary
RUN set -eux; \
        TRIVY_VERSION="0.69.3"; \
        ARCH="$(dpkg --print-architecture)"; \
        case "$ARCH" in \
            amd64) TRIVY_ARCH="64bit" ;; \
            arm64) TRIVY_ARCH="ARM64" ;; \
            *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
        esac; \
        wget -qO /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
        tar -xzf /tmp/trivy.tar.gz -C /tmp trivy; \
        mv /tmp/trivy /usr/local/bin/trivy; \
        chmod +x /usr/local/bin/trivy; \
        rm -f /tmp/trivy.tar.gz

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install liboqs and Python bindings for production quantum mode
RUN set -eux; \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs; \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON; \
    cmake --build /tmp/liboqs/build; \
    cmake --install /tmp/liboqs/build; \
    ldconfig; \
    pip install --no-cache-dir liboqs-python; \
    rm -rf /tmp/liboqs

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /var/lib/seraph-ai/vpn \
    && mkdir -p /app/scripts \
    && mkdir -p /app/playbooks \
    && mkdir -p /app/services \
    && chmod -R 755 /app

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/api/health || exit 1

# Run the application with CCE Worker
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
