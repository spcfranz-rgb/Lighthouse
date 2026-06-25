# Use a lightweight Python base image
FROM python:3.9-slim

# Install system dependencies, determine CPU architecture, fetch Ookla native binary, and clean up
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

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY . .

# Expose the port the web GUI will run on
EXPOSE 5000

# Boot the container using Gunicorn with Eventlet async workers
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
