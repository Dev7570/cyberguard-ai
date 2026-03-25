# CyberGuard - AI: Real-Time Network Threat Intelligence Platform

<p align="center">
  <strong>🛡️ ML-Powered Network Threat Detection & Visualization</strong>
</p>

<p align="center">
  <em>Developed by <strong>Dev Gupta</strong></em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Next.js-14-black?logo=next.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-3.0-green?logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/ML-scikit--learn-orange?logo=scikit-learn&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</p>

---

## Overview

CyberGuard - AI is a production-ready network threat intelligence platform that combines **machine learning** with **rule-based heuristics** to detect and visualize network threats in real time.

### Why This is Useful

In modern networks, traditional signature-based firewalls often fail to catch zero-day attacks or slow, methodical intrusions. CyberGuard-AI solves this by:
- **Identifying Anomalies Instantly:** Using Isolation Forests to detect traffic that behaves strangely, even if there's no known signature for it.
- **Providing Immediate Actionability:** Visualizing raw packet streams into understandable metrics and top-attacker charts so you can make split-second decisions.
- **Automating Defense:** Offering instant IP blocking capabilities and automated threat scoring to prioritize critical risks above all else.

### Key Features

- **🤖 Dual ML Engine** — Random Forest classifier + Isolation Forest anomaly detector
- **🔍 8 Attack Detectors** — SYN flood, port scan, brute force, DDoS, DNS amplification, Xmas/Null scans
- **📊 Real-Time Dashboard** — Premium dark-themed UI with live charts, threat table, and top attackers
- **🚫 IP Blocking** — One-click blocking with persistent blocklist
- **🎭 Simulation Mode** — Generates realistic attack traffic for demo/development
- **📡 Live Capture Mode** — Real network monitoring using psutil (no Npcap required)
- **💾 SQLite Persistence** — Threat logs survive server restarts
- **🔌 WebSocket** — Real-time push updates to connected dashboards

---

## Architecture

```
┌─────────────────┐     HTTP/WS      ┌──────────────────┐
│                 │ ◄──────────────── │                  │
│   ML Backend    │                   │  Next.js         │
│   (Flask)       │ ──────────────►   │  Dashboard       │
│                 │   JSON Threats    │                  │
├─────────────────┤                   └──────────────────┘
│ Network Monitor │                        :3000
│ ML Model (RF)   │
│ Isolation Forest│
│ Heuristic Rules │
│ SQLite DB       │
└─────────────────┘
      :5000
```

---

## Quick Start (Native — No Docker)

### Prerequisites

- **Python 3.10+** — [python.org](https://python.org)
- **Node.js 18+** — [nodejs.org](https://nodejs.org)
- **VS Code** — recommended IDE

### 1. Clone & Setup Backend

```bash
cd cyberguard-ai/cyberguard-backend

# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the backend
python app.py
```

You should see:
```
Model trained — accuracy: 0.95+
CyberGuard-AI backend starting on port 5000
Simulated network monitor started
```

### 2. Setup Dashboard

Open a **new terminal** in VS Code (Ctrl+Shift+`):

```bash
cd cyberguard-ai/cyberguard-dashboard

# Install dependencies
npm install

# Start development server
npm run dev
```

### 3. Open the Dashboard

Navigate to **http://localhost:3000** in your browser. The dashboard will automatically connect to the backend and display real-time threat data.

---

## Quick Start (Docker)

```bash
cd cyberguard-ai
docker-compose up --build
```

- Dashboard: http://localhost:3000
- API: http://localhost:5000

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check & system status |
| `GET` | `/stats` | Aggregated threat statistics |
| `GET` | `/threats?limit=100&level=CRITICAL` | Get threats (filterable) |
| `POST` | `/predict` | Analyze packets (JSON array) |
| `POST` | `/block` | Block an IP `{"ip": "x.x.x.x"}` |
| `POST` | `/unblock` | Unblock an IP |
| `GET` | `/blocked` | List all blocked IPs |
| `GET` | `/network/interfaces` | List network interfaces |
| `GET` | `/network/stats` | System network counters |
| `GET` | `/settings` | Get all settings |
| `POST` | `/settings` | Update settings |
| `GET` | `/model/info` | ML model details & feature importance |
| `POST` | `/reset` | Clear all threat data |

### Example: Send Test Packets

```bash
curl -X POST http://127.0.0.1:5000/predict ^
  -H "Content-Type: application/json" ^
  -d "[{\"src_ip\":\"45.227.255.200\",\"dst_ip\":\"192.168.1.10\",\"src_port\":54321,\"dst_port\":22,\"protocol\":\"TCP\",\"packet_size\":200,\"flags\":2,\"timestamp\":\"2025-01-01T00:00:00\"}]"
```

---

## Project Structure

```
cyberguard-ai/
├── cyberguard-backend/
│   ├── app.py              # Flask API + WebSocket server
│   ├── ml_model.py         # Random Forest + Isolation Forest
│   ├── data_processor.py   # Feature extraction + heuristic rules
│   ├── network_monitor.py  # Simulated & live network capture
│   ├── database.py         # SQLite persistence layer
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile
├── cyberguard-dashboard/
│   ├── src/pages/index.js  # Main dashboard page
│   ├── src/styles/         # CSS design system
│   ├── .env.local          # API URL config
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## ML Model Details

### Features (15 dimensions)

| # | Feature | Description |
|---|---------|-------------|
| 0 | src_port | Source port number |
| 1 | dst_port | Destination port number |
| 2 | packet_size | Packet size in bytes |
| 3 | is_tcp | TCP protocol flag |
| 4 | is_udp | UDP protocol flag |
| 5 | is_icmp | ICMP protocol flag |
| 6 | tcp_flags | Raw TCP flag value |
| 7 | packets_per_sec | Cumulative packets/sec from source |
| 8 | bytes_per_sec | Cumulative bytes/sec from source |
| 9 | unique_dst_ports | Unique destination ports seen |
| 10 | port_diversity | Port diversity ratio |
| 11 | syn_ratio | SYN packet ratio |
| 12 | burst_rate | Recent burst rate (5s window) |
| 13 | port_entropy | Shannon entropy of ports |
| 14 | suspicious_port | Known suspicious port flag |

### Attack Detection

| Attack Type | Detection Method | Heuristic Score |
|------------|-----------------|-----------------|
| SYN Flood | High SYN ratio (>80%) | +45 |
| Port Scan | High port diversity (>0.6) | +35 |
| DDoS | High pps (>100/sec) | +40 |
| Brute Force | Repeated auth port access | +30 |
| DNS Amplification | Large DNS responses (>512B) | +40 |
| Xmas Scan | FIN+PSH+URG flags | +35 |
| Null Scan | Zero TCP flags | +30 |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `venv\Scripts\activate` fails | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Port 5000 in use | Change `PORT=5001` in app.py and update `.env.local` |
| CORS errors in browser | Verify `CORS(app)` is in app.py after `Flask(__name__)` |
| Dashboard shows "Disconnected" | Ensure Flask backend is running on port 5000 |
| `ModuleNotFoundError` | Ensure `(venv)` is active before running `python app.py` |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
