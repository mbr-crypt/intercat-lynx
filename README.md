<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/lynx-logo-weiss.svg">
  <img src="docs/assets/logo/lynx-logo-schwarz.svg" alt="InterCat Lynx" width="360">
</picture>

**Vulnerability intelligence**

Track CVEs and security threats, and get told about the ones that concern your systems.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Next.js](https://img.shields.io/badge/next.js-14-black.svg)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/postgresql-16-blue.svg)](https://www.postgresql.org/)

[About this fork](#-about-this-fork) • [Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🧬 About this fork

**InterCat Lynx** is a fork of [OpenThreat](https://github.com/hoodinformatik/OpenThreat) by
[hoodinformatik](https://github.com/hoodinformatik). The original project is no longer maintained
(last change on 2026-08-23). Lynx keeps its history and licence, fixes bugs and extends it.

What is different from the original (details in [CHANGELOG.md](CHANGELOG.md) and [NOTICE](NOTICE)):

- Setup assistant in the browser: system check, administrator, e-mail, NVD key and data import, protected by a one-time setup token
- Passwords hashed with Argon2id (old bcrypt hashes are upgraded on login), two-factor login with TOTP and recovery codes
- Working test suite, fixed database migrations, updated dependencies
- Planned: user management, product selection with notifications (e-mail, webhook, Zabbix), CVE trend graphs, SSO

Technical names (database `openthreat`, container names, environment variables) are unchanged for now so that existing installations keep working.

## 🎯 Mission

OpenThreat makes threat intelligence accessible to everyone - from security professionals to small businesses and non-profits. We aggregate vulnerability data from trusted public sources into a clear, actionable interface.

## ✨ Features

### 📊 Data & Intelligence
- **314,000+ CVEs** from NVD, CISA KEV, and BSI CERT-Bund
- **1,436 exploited vulnerabilities** actively tracked
- **Priority scoring** algorithm (exploitation + CVSS + recency)
- **LLM-powered descriptions** for better understanding
- **German security advisories** from BSI CERT-Bund

### 🔍 Search & Discovery
- **Advanced search** with multiple filters
- **Full-text search** across all vulnerability data
- **Filter by severity**, vendor, product, CWE, CVSS score
- **Date range filtering** for recent threats

### 🚀 Integration & Automation
- **REST API** with 20+ endpoints
- **RSS/Atom feeds** for monitoring
- **Background tasks** with Celery
- **Automatic data updates** from multiple sources

### 💻 User Experience
- **Modern web interface** built with Next.js
- **Real-time statistics** dashboard
- **Detailed CVE pages** with actionable insights
- **Responsive design** for mobile and desktop

## 🚀 Quick Start

> 💡 **Neu hier?** Siehe [QUICK_START.md](QUICK_START.md) für eine Schritt-für-Schritt Anleitung!

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Python 3.13+](https://www.python.org/downloads/)
- [Node.js 18+](https://nodejs.org/)

### One-Command Start

**Windows:**
```bash
.\start.bat
```

**Manual Setup:**

1. **Clone the repository**
```bash
git clone https://github.com/mbr-crypt/intercat-lynx.git
cd intercat-lynx
```

2. **Start infrastructure**
```bash
docker-compose up -d
```

3. **Set up backend**
```bash
# Install dependencies
pip install -r requirements.txt

# Create database tables
alembic upgrade head

# Or use the setup script (Windows)
.\setup_database.bat

# Populate database (choose one):
# Option A: Recent CVEs only (fast, recommended for first run)
python scripts/fetch_nvd_complete.py --recent --days 30

# Option B: All CVEs (takes hours, run overnight)
# python scripts/fetch_nvd_complete.py

# Fetch CISA KEV data (exploited vulnerabilities)
python scripts/fetch_cisa_kev.py

# Start backend (IMPORTANT: from project root, not from backend/)
python -m uvicorn backend.main:app --reload --port 8001

# Or use the batch script (Windows)
.\start_backend.bat
```

4. **Start frontend**
```bash
cd frontend
npm install
npm run dev

# Or use the batch script (Windows)
.\start_frontend.bat
```

5. **Verify the setup**
```bash
# Check stats (should show exploited vulnerabilities)
curl "http://localhost:8001/api/v1/stats"

# Check KEV status
curl "http://localhost:8001/api/v1/data-sources/cisa-kev/status"
```

6. **Access the application**
- 🌐 **Frontend**: http://localhost:3000
- 📚 **API Docs**: http://localhost:8001/docs
- 🔌 **API**: http://localhost:8001

## 📥 Populating the Database

After setup, you need to fetch vulnerability data. You have **3 options**:

### Option 1: API Endpoints (Recommended)

Use the Swagger UI at `http://localhost:8001/docs`:

1. Go to `/api/v1/data-sources/nvd/fetch-recent`
2. Set `days=30` (fetches last 30 days)
3. Click "Execute"
4. Wait 5-30 minutes

Or use curl:
```bash
# Fetch recent CVEs (fast)
curl -X POST "http://localhost:8001/api/v1/data-sources/nvd/fetch-recent?days=30"
```

**Note:** CISA KEV data should already be populated during initial setup. If not, run:
```bash
python scripts/fetch_cisa_kev.py
```

### Option 2: CLI Script

```bash
# Recent CVEs only (recommended)
python scripts/fetch_nvd_complete.py --recent --days 30

# All CVEs (300,000+, takes hours!)
python scripts/fetch_nvd_complete.py

# With API key (5x faster)
export NVD_API_KEY=your_key_here
python scripts/fetch_nvd_complete.py --recent --days 30
```

### Option 3: Docker Exec (for Production)

If running in Docker:
```bash
# Execute script inside backend container
docker compose exec backend python scripts/fetch_nvd_complete.py --recent --days 30
```

### Get NVD API Key (Optional but Recommended)

- **Without key**: 10 requests/min → ~10-15 hours for all CVEs
- **With key**: 50 requests/min → ~2-3 hours for all CVEs

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

Add to `.env`:
```bash
NVD_API_KEY=your_api_key_here
```

### Check Database Status

```bash
# Via API
curl "http://localhost:8001/api/v1/stats/overview"

# Via API (detailed)
curl "http://localhost:8001/api/v1/data-sources/list"
```

## 📊 Data Sources

We aggregate data from trusted public sources:

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities | Daily |
| [NVD](https://nvd.nist.gov/) | National Vulnerability Database | Every 2 hours |
| [BSI CERT-Bund](https://wid.cert-bund.de/) | German Security Advisories | Daily |  

## 🏗️ Architecture

```
┌──────────────────────────────────────────────┐
│           Frontend (Next.js 14)              │
│     Modern UI with TailwindCSS               │
│            Port 3000                         │
└────────────────┬─────────────────────────────┘
                 │ REST API
                 ▼
┌──────────────────────────────────────────────┐
│        Backend API (FastAPI)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   API    │  │  Celery  │  │   LLM    │  │
│  │Endpoints │  │  Tasks   │  │ Service  │  │
│  └──────────┘  └──────────┘  └──────────┘  │
│            Port 8001                         │
└────────────────┬─────────────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌──────────────┐  ┌──────────────┐
│ PostgreSQL   │  │    Redis     │
│   Port 5432  │  │   Port 6379  │
└──────────────┘  └──────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## 🔧 Local Development

### API Routing (Development vs Production)

The frontend uses relative API paths (e.g., `/api/v1/auth/register`). These work differently depending on the environment:

**Development (local):**
- Next.js Rewrites automatically forward API requests to `http://127.0.0.1:8001`
- Configured in `frontend/next.config.js`
- No additional configuration needed

**Production:**
- Nginx routes all requests (Frontend + Backend)
- Configured in `nginx/nginx.conf`

### Local Testing with Nginx (Optional)

If you want to replicate the production environment locally:

```bash
# Use the development nginx configuration
docker run -d \
  --name openthreat-nginx \
  -p 80:80 \
  -v $(pwd)/nginx/nginx.dev.conf:/etc/nginx/nginx.conf:ro \
  --add-host host.docker.internal:host-gateway \
  nginx:alpine
```

See [nginx/README.md](nginx/README.md) for details.

## **Documentation**

### Getting Started
- [Quick Start Guide](QUICK_START.md) - 5-Minute Setup
- [Development Setup](DEVELOPMENT_SETUP.md) - Local Development & Troubleshooting
- [Nginx Configuration](nginx/README.md) - Routing & Reverse Proxy

### Technical Documentation
- [API Documentation](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Database Schema](docs/DATABASE.md)
- [BSI Integration](docs/BSI_INTEGRATION.md)
- [Security](docs/SECURITY.md)
- [Testing Guide](docs/TESTING.md)
- [Monitoring Guide](docs/MONITORING.md)
- [Development Progress](PROGRESS.md)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick Links:**
- [Report a Bug](https://github.com/mbr-crypt/intercat-lynx/issues/new?labels=bug)
- [Request a Feature](https://github.com/mbr-crypt/intercat-lynx/issues/new?labels=enhancement)
- [View Changelog](CHANGELOG.md)

## 📧 Contact

- **This fork:** [mbr-crypt/intercat-lynx](https://github.com/mbr-crypt/intercat-lynx) (issues and pull requests)
- **Original project:** [hoodinformatik/OpenThreat](https://github.com/hoodinformatik/OpenThreat)

## 📜 License

GNU Affero General Public License v3.0 (AGPL-3.0), see [LICENSE](LICENSE).

The original OpenThreat README stated "Apache 2.0", but the `LICENSE` file in the repository is the AGPL-3.0,
so this fork follows the `LICENSE` file. Origin and changes are described in [NOTICE](NOTICE).

If you run a modified version as a network service, the AGPL requires you to offer your users the source
code of that version. The web interface links to the source code in its footer.

### Names and logos

The names **"Intercat"** and **"InterCat Lynx"** and the logos of **Intercat** and **InterCat Lynx** are the
property of Moritz Rehmann and are protected by his copyright (&copy; 2026 Moritz Rehmann, all rights reserved).
They are **not** part of the AGPL-3.0 licensed source code. You may not use them for your own product or
service. If you fork this project, please choose your own name and logo. Details are in [NOTICE](NOTICE).

## 🌟 Star History

If you find this useful, please consider giving the repository (and the original OpenThreat) a star! ⭐

---

<div align="center">

**Made with ❤️ for the security community**

[Report Bug](https://github.com/mbr-crypt/intercat-lynx/issues) • [Request Feature](https://github.com/mbr-crypt/intercat-lynx/issues) • [Documentation](docs/)

</div>
