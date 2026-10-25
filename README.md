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

> The path below is the one tested for installations: **Docker on Linux** (a server, a VM, or WSL2). You do not need Python or Node on the host, everything is built in containers. Step-by-step with troubleshooting: [QUICK_START.md](QUICK_START.md). Test plan for a fresh VM: [docs/PROD_TEST.md](docs/PROD_TEST.md).

### Requirements

- Linux with [Docker Engine](https://docs.docker.com/engine/install/) 24+ and the Compose plugin (`docker compose version` must work)
- `git` and `openssl`
- 4 GB RAM and 10 GB free disk (the first build downloads a few hundred MB)
- Internet access for the build and for the CVE import (NVD, CISA)

### Install

```bash
git clone https://github.com/mbr-crypt/intercat-lynx.git
cd intercat-lynx

./scripts/init-env.sh              # creates .env with random secrets
docker compose up -d --build       # first build takes several minutes
docker compose ps                  # wait until "backend" shows (healthy)
```

`init-env.sh` detects the address of the machine and writes it to `.env` as `PUBLIC_URL`. If you open the site under another name, pass it: `./scripts/init-env.sh http://lynx.example.org`.

Then open `PUBLIC_URL` in the browser. A fresh installation starts the **setup assistant**: it asks for the setup token (`grep SETUP_TOKEN .env`), creates the first administrator, offers two-factor login, mail settings and the first CVE import.

### HTTPS

The default is plain HTTP, which is fine for a first test. For anything beyond that:

- **Own certificate:** put `nginx.crt` and `nginx.key` into `nginx/ssl/`, set `NGINX_CONF=./nginx/nginx.conf` in `.env`, and set `PUBLIC_URL` to the `https://` address.
- **Quick self-signed test certificate:** `./scripts/init-env.sh https://your-host --https --force` (browsers will warn).
- **Another proxy does TLS** (company proxy, Cloudflare): keep the HTTP configuration and read the `TRUSTED_PROXIES` notes in `.env.example`.

### Everyday commands

```bash
docker compose logs -f backend     # follow the API log
docker compose ps                  # state and health of all services
docker compose restart backend     # after editing .env: docker compose up -d
docker compose down                # stop (data stays in volumes)
docker compose down -v             # stop AND delete the database (start over)
git pull && docker compose up -d --build   # update
```

### Something does not start?

| Message or symptom | Cause and fix |
|---|---|
| `required variable SECRET_KEY is missing` | There is no `.env`. Run `./scripts/init-env.sh`. |
| Backend exits with `SECRET_KEY ... is an example value` | `.env` was copied by hand and not filled in. Use `init-env.sh`, or set a random value of 32+ characters. |
| `port is already allocated` | Port 80/443 is taken. Set `HTTP_PORT` / `HTTPS_PORT` in `.env`, and add the port to `PUBLIC_URL`. |
| `backend` stays `starting`, then `unhealthy` | `docker compose logs backend`. The most common reason is a wrong database password after changing `.env` on an existing database: `docker compose down -v` to start fresh. |
| nginx restarts, log says `cannot load certificate` | `NGINX_CONF` points to the HTTPS file but `nginx/ssl/` is empty. Use `nginx.http.conf` or create the certificate. |
| Setup assistant asks for a token you do not have | `grep SETUP_TOKEN .env`. If it is empty: `docker compose logs backend \| grep -A3 "not set up"`. |
| Forgot the administrator password | See [QUICK_START.md](QUICK_START.md#forgot-the-administrator-password). |

## 📥 Populating the Database

The setup assistant offers the first import. You can also run it by hand at any time; the CVE data comes from the NVD and CISA KEV:

```bash
# Recent CVEs only (fast, recommended for the first run)
docker compose exec backend python scripts/fetch_nvd_complete.py --recent --days 30

# CISA KEV (actively exploited vulnerabilities)
docker compose exec backend python scripts/fetch_cisa_kev.py

# Everything (300,000+ CVEs, takes hours)
docker compose exec backend python scripts/fetch_nvd_complete.py
```

After that the scheduler (`celery-beat`) keeps the data current.

### NVD API key (optional but recommended)

- **Without key:** about 10 requests per minute, the full import takes 10-15 hours
- **With key:** about 50 requests per minute, 2-3 hours

Get a free key at https://nvd.nist.gov/developers/request-an-api-key, put it into `.env` as `NVD_API_KEY=...` (or enter it in the setup assistant) and run `docker compose up -d`.

### Check the database

```bash
curl http://localhost/api/v1/stats           # numbers shown on the dashboard
curl http://localhost/health                 # API and database reachable
docker compose exec postgres psql -U openthreat -c "select count(*) from vulnerabilities;"
```

## 📊 Data Sources

We aggregate data from trusted public sources:

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities | Daily |
| [NVD](https://nvd.nist.gov/) | National Vulnerability Database | Every 2 hours |
| BSI CERT-Bund | German Security Advisories (CSAF feed, index data with link to the original) | every 3 hours, see [docs/BSI_INTEGRATION.md](docs/BSI_INTEGRATION.md) |

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

For working on the code, only the database and Redis run in Docker; backend and frontend run on your machine. Details and troubleshooting: [DEVELOPMENT_SETUP.md](DEVELOPMENT_SETUP.md).

```bash
docker compose -f docker-compose.dev.yml up -d      # PostgreSQL + Redis
pip install -r requirements.txt
alembic upgrade head
python -m uvicorn backend.main:app --reload --port 8001   # from the project root
cd frontend && npm install && npm run dev                  # http://localhost:3000
```

### API routing (development vs. Docker)

The frontend always uses relative API paths (e.g. `/api/v1/auth/login`). Who forwards them depends on the setup:

- **Development:** Next.js rewrites forward `/api` to `http://127.0.0.1:8001` (`frontend/next.config.js`).
- **Docker:** nginx routes everything: `/api` to the backend, the rest to the frontend (`nginx/nginx.http.conf` or `nginx/nginx.conf`).

See [nginx/README.md](nginx/README.md) for details.

## **Documentation**

### Getting Started
- [Quick Start Guide](QUICK_START.md) - Docker installation step by step
- [Test plan for a fresh VM](docs/PROD_TEST.md) - what to check after installing
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
