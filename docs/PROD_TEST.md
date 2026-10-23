# Test plan: fresh installation on a clean VM

Purpose: prove that the documented installation path works on a machine that has never seen the project, and find what does not. Go through the sections in order and write down every deviation, even a small one.

Recommended machine: a fresh **Ubuntu Server 24.04 LTS** VM, 2 vCPU, 4 GB RAM, 20 GB disk, network reachable from your workstation. Linux is what the project is built and tested for; Docker Desktop on Windows adds its own variables (WSL2, file sharing, line endings) and should be a separate test later.

Do not copy anything from an older installation (no old `.env`, no old volumes). If you reuse a VM: `docker compose down -v` and delete the project folder.

## 0. What was and was not verified before this test

Already checked in the development environment: unit tests (SQLite), `docker compose config`, `nginx -t` for both nginx files, the frontend build, the shell scripts' syntax and behavior.

**Not yet verified, and the point of this test:**

- the Docker images build on a clean machine
- the database migrations 012-016 on a real PostgreSQL
- the startup order with real healthchecks (PostgreSQL, Redis, backend, nginx)
- nginx with real container names, the Redis rate limiter, and the Celery worker with the encrypted settings
- the setup assistant in a browser, end to end

## 1. Install Docker (once per VM)

```bash
sudo apt update && sudo apt install -y git openssl curl ca-certificates
# Docker Engine + Compose plugin: follow https://docs.docker.com/engine/install/ubuntu/
sudo usermod -aG docker $USER      # log out and in again
docker --version && docker compose version
```

☐ `docker compose version` prints a version

## 2. Install the project (exactly as in QUICK_START.md)

```bash
git clone https://github.com/mbr-crypt/intercat-lynx.git
cd intercat-lynx
git checkout <branch under test>        # only while the change is not merged yet
./scripts/init-env.sh
docker compose up -d --build
docker compose ps
```

☐ `init-env.sh` prints no error and shows the right address (if not, rerun with the address as argument)
☐ the build finishes without error (note the duration)
☐ within 3 minutes: `postgres`, `redis`, `backend` are `healthy`; `nginx`, `frontend`, `celery-worker`, `celery-beat` are `running`
☐ `docker compose logs backend | grep -i "error\|traceback"` shows nothing alarming (note anything it does show)
☐ the log contains `Upgrading database schema (alembic)` and no `Schema upgrade failed`

## 3. Smoke tests from the VM

```bash
curl -s http://localhost/health                   # healthy, database healthy
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/              # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/metrics       # 404
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/health/detailed   # 404
curl -s http://localhost/api/v1/setup/status      # {"setup_required":true,...}
ss -tlnp | grep -E ':(80|443|5432|6379|8001|3000)\b'   # only 80 (and 443) listen; no 5432/6379/8001/3000
```

☐ results match the comments
☐ PostgreSQL, Redis, backend and frontend are NOT reachable from another machine (try `nc -zv <vm-ip> 5432` from your workstation)

## 4. Setup assistant in the browser (from your workstation)

Open `PUBLIC_URL`.

☐ the start page is the setup assistant, not the dashboard
☐ a wrong token is refused, the correct one (`grep SETUP_TOKEN .env`) is accepted
☐ the system check is all green (database, key, encryption, Redis, internet)
☐ administrator can be created; a password under 12 characters is refused
☐ 2FA setup works with an authenticator app (scan, confirm code), and login afterwards asks for the code
☐ mail settings: enter real SMTP data, "send test mail" arrives (skip if no SMTP yet, but note it)
☐ first import starts and shows progress; it finishes (with an NVD key about 5-10 minutes for 30 days)
☐ after finishing, `http://<vm>/api/v1/setup/status` no longer asks for setup and the dashboard shows CVE numbers

## 5. Functions that need the whole stack

☐ dashboard: numbers, trend graph, "exploited" (KEV) counts
☐ CVE search and a CVE detail page
☐ My Products: select a product, see matching CVEs
☐ Notifications: create a rule with a webhook (a test URL such as a free webhook inspector) or mail, trigger "test"; the message arrives (this exercises the Celery worker and the decryption of stored secrets)
☐ Zabbix endpoint/template (if you use Zabbix): create an API token, `curl -H "Authorization: Bearer <token>" http://<vm>/api/v1/zabbix/summary`
☐ Admin area: user list, create a second user, reset its password
☐ login lockout: five wrong passwords lock the account temporarily
☐ rate limit: `for i in $(seq 1 80); do curl -s -o /dev/null -w "%{http_code} " http://localhost/api/v1/stats; done` shows some `429`
☐ real client address: `docker compose logs nginx | tail` shows your workstation's address, and the backend's lockouts/limits refer to it (not to a Docker address)

## 6. Robustness

☐ `docker compose restart backend`, then the site works again without restarting anything else (note if nginx needs a restart: `docker compose restart nginx`)
☐ `docker compose down && docker compose up -d`: data is still there, no setup assistant
☐ reboot the VM: the stack starts by itself (`restart: unless-stopped`)
☐ `docker compose exec backend python scripts/reset_password.py <admin>` works (then log in with the new password, which must be changed immediately)
☐ `docker compose exec postgres pg_dump -U openthreat openthreat | gzip > backup.sql.gz` produces a non-empty file

## 7. HTTPS variant (second run)

```bash
docker compose down -v && rm .env
./scripts/init-env.sh https://<vm-ip-or-name> --https
docker compose up -d --build
```

☐ `https://<vm>` loads (certificate warning is expected), `http://<vm>` redirects to https
☐ `curl http://localhost/health` still answers over HTTP (deployment checks)
☐ the setup assistant and login work over HTTPS

## 8. Report

For every unchecked box note: the command, the output (without secrets), and `docker compose logs` of the affected service. The important findings go into the vault under "InterCat Lynx - Offene Punkte".

## What this test does not cover

- Load and performance with the full CVE set (300,000+ entries)
- Windows with Docker Desktop
- Security review by a third party (planned, see roadmap "Härtung und SSO")
- Real BSI/CERT-Bund data (not rebuilt yet)
