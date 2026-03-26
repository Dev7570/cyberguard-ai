# CyberGuard-AI: Autonomous Network Threat Intelligence Platform

<p align="center">
  <strong>🛡️ ML-Powered Threat Detection · Autonomous Recovery · Global Geo-Fencing · Real-Time Analytics</strong>
</p>

<p align="center">
  <em>Developed by <strong>Dev Gupta</strong></em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Next.js-14-black?logo=next.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-3.0-green?logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/ML-scikit--learn-orange?logo=scikit-learn&logoColor=white" />
  <img src="https://img.shields.io/badge/WebSocket-Socket.IO-purple?logo=socket.io&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</p>

---

## Overview

CyberGuard-AI is a **production-ready, autonomous** network threat intelligence platform that combines **dual ML engines** with **rule-based heuristics** to detect, visualize, and neutralize network threats in real time. Unlike traditional firewalls, CyberGuard-AI thinks for itself — autonomously blocking threats, recovering safe IPs, and alerting operators via webhooks.

### What Makes This Different

| Traditional Firewall | CyberGuard-AI |
|---------------------|---------------|
| Signature-based detection | ML anomaly detection (catches zero-day attacks) |
| Manual rule management | Autonomous blocking & recovery with AI reasoning |
| Static logs | Real-time dashboard with global threat map |
| No geographical context | Country-level geo-fencing & Geo-IP mapping |
| No proactive alerts | Instant Discord/Slack webhook notifications |
| No export capability | One-click CSV forensic export |

---

## Features

### 🤖 Dual ML Engine
- **Random Forest** classifier trained on 15 engineered features for threat classification
- **Isolation Forest** anomaly detector for zero-day attack identification
- Combined threat scoring with heuristic boosting

### 🔍 8 Attack Detectors
SYN Flood · Port Scan · DDoS · Brute Force · DNS Amplification · Xmas Scan · Null Scan · Data Exfiltration

### 🧠 AI-Driven Reasoning
- Every blocked IP receives an AI-generated explanation (why it was blocked, confidence level)
- Unblock recommendations for safe IPs with detailed reasoning

### 🔄 Autonomous Recovery Loop
- Background thread continuously evaluates blocked IPs
- Auto-unblocks IPs with low threat history after a cooldown period
- Sends webhook alerts when IPs are recovered

### 🌍 Global Geo-IP Threat Map
- Real-time SVG world map with pulsing threat markers
- IP geolocation via ipapi.co (country, city, coordinates)
- Hover tooltips with detailed location info

### 🛡️ Country-Level Geo-Fencing
- Block entire countries from the dashboard
- Packets from banned regions are intercepted before ML analysis
- Geo-fence violations trigger instant webhook alerts

### 🔔 Instant Webhook Notifications
- Discord/Slack-compatible rich embeds for every critical event
- Configurable webhook URL via the Settings modal
- Test button for verifying connectivity

### 📊 24h Threat Analytics
- Summary badges with color-coded severity breakdown
- Hourly trend chart (AreaChart with critical overlay)
- Top attack types ranking
- One-click CSV export for forensic reporting

### 📡 Real-Time Architecture
- WebSocket push updates via Socket.IO
- Live threat table with severity filtering
- Pause/Resume controls for monitoring

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   NEXT.JS DASHBOARD (:3000)          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │
│  │ Analytics │ │ Threat   │ │ Geo-IP   │ │Security│  │
│  │ Charts   │ │ Table    │ │ Map      │ │ Rules  │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘  │
└─────────────────────┬────────────────────────────────┘
                      │ HTTP / WebSocket
┌─────────────────────▼────────────────────────────────┐
│                FLASK BACKEND (:5000)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │
│  │ ML Model │ │ Packet   │ │ Geo-IP   │ │Webhook │  │
│  │ (RF+IF)  │ │Processor │ │ Resolver │ │ Engine │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │ Network  │ │ SQLite   │ │ Recovery │             │
│  │ Monitor  │ │ Database │ │ Loop     │             │
│  └──────────┘ └──────────┘ └──────────┘             │
└──────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- **Python 3.10+** — [python.org](https://python.org)
- **Node.js 18+** — [nodejs.org](https://nodejs.org)

### 1. Backend

```bash
cd cyberguard-ai/cyberguard-backend

# Create & activate venv
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install & run
pip install -r requirements.txt
python app.py
```

### 2. Dashboard

```bash
cd cyberguard-ai/cyberguard-dashboard
npm install
npm run dev
```

### 3. Open
Navigate to **http://localhost:3000** — the dashboard auto-connects to the backend.

---

## Docker Quick Start

```bash
cd cyberguard-ai
docker-compose up --build
```

- Dashboard: http://localhost:3000
- API: http://localhost:5000

---

## API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check & system status |
| `GET` | `/stats` | Aggregated threat statistics |
| `GET` | `/threats?limit=100&level=CRITICAL` | Get threats (filterable) |
| `POST` | `/predict` | Analyze packets (JSON array) |
| `POST` | `/block` | Block an IP `{"ip": "x.x.x.x"}` |
| `POST` | `/unblock` | Unblock an IP |
| `GET` | `/blocked` | Blocked IPs with AI recommendations |

### Analytics & Export

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/threats/history?hours=24` | Paginated threat history |
| `GET` | `/threats/summary` | 24h aggregated analytics |
| `GET` | `/threats/export?hours=24` | Download CSV report |

### Country-Level Blocking

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/countries/blocked` | List blocked countries |
| `POST` | `/countries/block` | Block a country `{"country_code": "CN", "country_name": "China"}` |
| `POST` | `/countries/unblock` | Unblock a country |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/settings` | Get all settings |
| `POST` | `/settings` | Update settings (webhook_url, simulation_mode, etc.) |
| `POST` | `/test-webhook` | Send a test webhook notification |
| `POST` | `/reset` | Clear all threat data |
| `GET` | `/model/info` | ML model details & feature importance |

---

## Project Structure

```
cyberguard-ai/
├── cyberguard-backend/
│   ├── app.py              # Flask API + WebSocket + Recovery Loop
│   ├── ml_model.py         # Random Forest + Isolation Forest
│   ├── data_processor.py   # Feature extraction + heuristic rules
│   ├── network_monitor.py  # Simulated & live network capture
│   ├── database.py         # SQLite persistence + analytics queries
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile
├── cyberguard-dashboard/
│   ├── src/pages/index.js  # Main dashboard (Analytics, Map, Rules)
│   ├── src/components/     # ThreatMap, ChartTooltip components
│   ├── src/styles/         # Cyberpunk CSS design system
│   ├── .env.local          # API URL config
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## ML Model Details

### Feature Engineering (15 dimensions)

| # | Feature | Description |
|---|---------|-------------|
| 0 | src_port | Source port number |
| 1 | dst_port | Destination port number |
| 2 | packet_size | Packet size in bytes |
| 3-5 | is_tcp/udp/icmp | Protocol one-hot flags |
| 6 | tcp_flags | Raw TCP flag value |
| 7 | packets_per_sec | Cumulative rate from source |
| 8 | bytes_per_sec | Cumulative bandwidth from source |
| 9 | unique_dst_ports | Unique destination ports seen |
| 10 | port_diversity | Port diversity ratio |
| 11 | syn_ratio | SYN packet ratio |
| 12 | burst_rate | Recent burst rate (5s window) |
| 13 | port_entropy | Shannon entropy of ports |
| 14 | suspicious_port | Known suspicious port flag |

### Attack Detection Matrix

| Attack Type | Detection Method | Score Boost |
|------------|-----------------|-------------|
| SYN Flood | SYN ratio > 80% | +45 |
| Port Scan | Port diversity > 0.6 | +35 |
| DDoS | Rate > 100 pps | +40 |
| Brute Force | Repeated auth port access | +30 |
| DNS Amplification | DNS response > 512B | +40 |
| Xmas Scan | FIN+PSH+URG flags | +35 |
| Null Scan | Zero TCP flags | +30 |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `venv\Scripts\activate` fails | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Port 5000 in use | Change `PORT=5001` in app.py and update `.env.local` |
| CORS errors in browser | Verify `CORS(app)` is in app.py |
| Dashboard shows "Disconnected" | Ensure backend is running on port 5000 |
| `ModuleNotFoundError` | Ensure `(venv)` is active before running |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
