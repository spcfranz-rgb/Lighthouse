# CCTVMonitor-NOC

A production-grade Edge Network Operations Center (NOC) gateway designed for Raspberry Pi 5 deployments. This system provides deep remote management, camera health monitoring, and network diagnostics for on-site CCTV LANs, strictly secured behind a Headscale/Tailscale VPN mesh.

## 🏗️ Architecture & Tech Stack

This gateway completely decouples the application from the physical hardware host using Docker, allowing for safe, automated CI/CD deployments via Komodo without risking local SD card corruption.

* **Backend:** Python, Flask, Flask-SocketIO
* **Concurrency:** Gunicorn with Eventlet asynchronous workers
* **Database:** SQLite3 (WAL mode) with `tmpfs` high-speed RAM-disk buffering
* **Message Broker:** Eclipse Mosquitto (MQTT)
* **Authentication:** Authentik OIDC (SSO) with local emergency fallback
* **Containerization:** Docker & Docker Compose (`network_mode: host`)

## ✨ Key Features

* **Layer-2 Hardware Discovery:** Bypasses standard Docker bridge NAT to perform true raw-socket ARP sweeps and ping physical MAC addresses on the local LAN.
* **Native Network Diagnostics:** Integrates the official Ookla Speedtest binary with custom UDP socket routing to force latency probes out of the physical WAN interface, bypassing the internal VPN tunnel.
* **Flash-Wear Protection:** Utilizes a Docker `tmpfs` volume to process high-frequency MQTT writes entirely in memory, safely syncing to the physical SD card in batch operations to prevent drive burnout.
* **Co-Branding Engine:** Dynamically fetches and renders company and customer logos via environment variables.

## 🚀 Deployment (Komodo / CI/CD)

This stack is designed to be deployed automatically via Komodo webhooks. 

### 1. Pre-Stage Persistent Storage
To prevent database wipes when Komodo reclones the repository, the stack uses a **Hybrid Volume Mount** strategy. Configuration files are pulled fresh from GitHub, while databases and logs are stored absolutely on the host.

Before deploying, create the persistent directories on the Raspberry Pi:
```bash
sudo mkdir -p /opt/cctv-data/dashboard
sudo mkdir -p /opt/cctv-data/mosquitto/data
sudo mkdir -p /opt/cctv-data/mosquitto/log
sudo chmod -R 777 /opt/cctv-data****
