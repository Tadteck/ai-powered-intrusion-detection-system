# AI-Powered Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikitlearn)
![License](https://img.shields.io/badge/License-MIT-purple)

**A full-stack AI-powered network intrusion detection system using Machine Learning.**

</div>

---

## 🧠 Overview

This system uses **Isolation Forest** (unsupervised anomaly detection) combined with rule-based heuristics to detect malicious network activity in real time. It provides a REST API backend and a modern web dashboard frontend.

## 🏗️ Architecture

```
├── Backend/          # Python FastAPI REST API
│   ├── app/
│   │   ├── api/      # API routes and endpoints
│   │   ├── core/     # Config, DB, Security, Logging
│   │   ├── models/   # SQLAlchemy ORM models
│   │   ├── schemas/  # Pydantic request/response schemas
│   │   └── services/ # Business logic (ML, Alerts, Users)
│   ├── tests/        # Unit and integration tests
│   └── main.py       # Application entry point
└── Frontend/         # React/TypeScript dashboard (coming soon)
```

## 🔥 Features

- 🤖 **AI Detection** - Isolation Forest anomaly detection with automatic alerting
- 🔐 **JWT Auth** - Secure token-based authentication
- 📊 **Dashboard Stats** - Real-time aggregated statistics
- 🚨 **Auto Alerts** - Automatic severity-graded alert creation
- 📡 **Event Ingestion** - REST endpoint for network agents to submit events
- 🔄 **Model Retraining** - Trigger retraining via API as data grows
- 📁 **Async SQLite/PostgreSQL** - Async database with SQLAlchemy
- 📝 **Structured Logging** - Loguru-based logging with rotation

## 🚀 Quick Start (Backend)

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
cd Backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate    # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start the server
python main.py
```

The API will be available at:
- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register a new user |
| POST | `/api/v1/auth/login` | Login and get JWT token |
| GET | `/api/v1/dashboard/stats` | Dashboard statistics |
| GET | `/api/v1/alerts/` | List all alerts |
| POST | `/api/v1/alerts/` | Create manual alert |
| PATCH | `/api/v1/alerts/{id}` | Update alert status |
| GET | `/api/v1/events/` | List network events |
| POST | `/api/v1/events/ingest` | Ingest network event for analysis |
| GET | `/api/v1/ml/status` | ML model status |
| POST | `/api/v1/ml/train` | Trigger model retraining |
| POST | `/api/v1/ml/predict` | Predict anomaly on a single event |

## 🧪 Testing

```bash
cd Backend
pytest tests/ -v
```

## 🛡️ Attack Types Detected

- Port Scanning
- Brute Force Attacks
- DoS / DDoS
- SQL Injection
- Cross-Site Scripting (XSS)
- Malware Traffic
- Data Exfiltration
- General Anomalies

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
