# ==========================================
# STAGE 1: Frontend Builder (Vue 3 / Vite)
# ==========================================
FROM node:20-alpine AS frontend-builder
WORKDIR /vue-app

# Install dependencies and build the SPA
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
# This compiles everything (including Bootstrap/Socket.io) into /vue-app/dist
RUN npm run build 

# ==========================================
# STAGE 2: Python Eventlet Backend (Project Lighthouse)
# ==========================================
FROM python:3.9-slim

# Install system dependencies, native binaries, and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        traceroute \
        ffmpeg \
        sqlite3 \
        curl \
        wget \
        tar \
        ca-certificates && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        wget -qO- https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz | tar xvz -C /usr/local/bin speedtest; \
    elif [ "$ARCH" = "amd64" ]; then \
        wget -qO- https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz | tar xvz -C /usr/local/bin speedtest; \
    else \
        echo "Unsupported architecture" && exit 1; \
    fi && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY . .

# CRITICAL: Ingest the compiled SPA from Stage 1 into Flask's static directory
COPY --from=frontend-builder /vue-app/dist /app/static

EXPOSE 5000

# Boot using Gunicorn with Eventlet
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
