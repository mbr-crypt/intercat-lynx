# 🚀 Quick Start

This guide installs InterCat Lynx with Docker on a Linux machine and walks you through the first start. It takes about 15 minutes, most of it waiting for the first build.

If you want to work on the code instead, see [DEVELOPMENT_SETUP.md](DEVELOPMENT_SETUP.md). If you want to check a fresh installation thoroughly, use the checklist in [docs/PROD_TEST.md](docs/PROD_TEST.md).

## 1. Prepare the machine

You need a Linux machine (a server, a VM, or WSL2 on Windows) with:

- Docker Engine 24 or newer **and the Compose plugin**
- `git` and `openssl`
- 4 GB RAM, 10 GB free disk space, internet access

Check Docker:

```bash
docker --version
docker compose version     # must print a version; "docker-compose" with a hyphen is the old tool
```

On Ubuntu, Docker is installed as described at https://docs.docker.com/engine/install/ubuntu/ (the packages `docker-ce` and `docker-compose-plugin`). Add yourself to the `docker` group (`sudo usermod -aG docker $USER`, then log in again) or put `sudo` in front of every `docker` command.

## 2. Get the code and create the configuration

```bash
git clone https://github.com/mbr-crypt/intercat-lynx.git
cd intercat-lynx
./scripts/init-env.sh
```

`init-env.sh` creates the file `.env` with random passwords and keys and writes the address of the machine into it. Nothing secret is printed. It refuses to overwrite an existing `.env`.

Which address will you type into the browser? The script detects the IP address of the machine. If you use a name (for example `lynx.example.org`) or the detection picks the wrong network, give it explicitly:

```bash
./scripts/init-env.sh http://192.168.1.50
```

## 3. Start

```bash
docker compose up -d --build
```

The first build downloads base images and compiles the frontend, which takes several minutes. Then check:

```bash
docker compose ps
```

All services should be `running`; `postgres`, `redis` and `backend` should say `(healthy)`. The backend needs up to a minute after starting because it creates the database tables first. If something is not healthy after three minutes, look at the log: `docker compose logs backend`.

Quick check from the machine itself:

```bash
curl http://localhost/health
# {"status":"healthy","database":"healthy",...}
```

## 4. Setup assistant

Open the address from step 2 in the browser. A fresh installation shows the setup assistant:

1. **Setup token:** the code that proves you are the owner. It is in `.env`:
   ```bash
   grep SETUP_TOKEN .env
   ```
2. **System check:** shows whether the database, the keys and the internet connection work.
3. **Administrator:** username, e-mail and a password of at least 12 characters.
4. **Two-factor login (recommended)** with an authenticator app.
5. **Mail server (optional):** needed for verification codes and alerts. You can skip it and enter it later.
6. **First import:** loads the recent CVEs in the background. A free NVD API key makes this much faster (https://nvd.nist.gov/developers/request-an-api-key).

When you finish, the assistant closes for good and the dashboard opens.

## 5. HTTPS (before anyone else uses it)

The default setup speaks plain HTTP. Passwords travel unencrypted, so use it only for a first test in a trusted network. Options:

- **You have a certificate:** copy `nginx.crt` and `nginx.key` into `nginx/ssl/`, set `NGINX_CONF=./nginx/nginx.conf` and the `https://` address in `PUBLIC_URL` in `.env`, then `docker compose up -d`.
- **Test certificate:** `./scripts/init-env.sh https://your-host --https --force` creates a self-signed one. Browsers warn about it. (`--force` creates a new `.env`; this is only for installations that have no data yet.)
- **A proxy in front already does HTTPS** (company proxy, Cloudflare): keep the HTTP file and read the `TRUSTED_PROXIES` notes in `.env.example`.

## Everyday commands

```bash
docker compose ps                          # what is running, is it healthy
docker compose logs -f backend             # follow the log (also: frontend, nginx, celery-worker)
docker compose up -d                       # apply changes made in .env
docker compose down                        # stop, data stays
docker compose down -v                     # stop and DELETE all data (database, Redis)
git pull && docker compose up -d --build   # update to the newest version
```

## Common problems

### `required variable SECRET_KEY is missing`

There is no `.env` yet. Run `./scripts/init-env.sh`.

### Backend restarts and the log says `SECRET_KEY ... is an example value`

`.env` was copied from `.env.example` by hand and the key was not replaced. Run `./scripts/init-env.sh --force` (only when you have no data yet) or set `SECRET_KEY` to a random value of at least 32 characters.

### `port is already allocated` or `address already in use`

Something else uses port 80 (or 443). Set `HTTP_PORT=8080` in `.env`, add the port to `PUBLIC_URL` (`http://192.168.1.50:8080`) and run `docker compose up -d`.

### `password authentication failed for user "openthreat"`

`POSTGRES_PASSWORD` in `.env` differs from the password the database was created with (Docker sets it only on the first start). If there is no data to keep: `docker compose down -v` and start again. Otherwise put the old password back.

### nginx restarts and the log mentions `nginx.crt`

`NGINX_CONF` points to the HTTPS file but `nginx/ssl/` has no certificate. Either create one (see HTTPS above) or set `NGINX_CONF=./nginx/nginx.http.conf`.

### The page loads but data is missing

The database is still empty. The first import runs from the setup assistant; to start it by hand:

```bash
docker compose exec backend python scripts/fetch_nvd_complete.py --recent --days 30
docker compose exec backend python scripts/fetch_cisa_kev.py
```

### Forgot the administrator password

Another administrator can reset it in the user management. If you are the only one, with shell access to the server:

```bash
docker compose exec backend python scripts/reset_password.py <username>
```

It asks for a new password and ends all existing logins. Add `--disable-2fa` if the authenticator app is lost too.

### Start from scratch

```bash
docker compose down -v
rm .env
./scripts/init-env.sh
docker compose up -d --build
```

## Further documentation

- [README.md](README.md): overview and features
- [docs/PROD_TEST.md](docs/PROD_TEST.md): checklist for a fresh installation
- [nginx/README.md](nginx/README.md): web server configuration
- [docs/MONITORING.md](docs/MONITORING.md): health endpoints, Prometheus, Zabbix
- [DEVELOPMENT_SETUP.md](DEVELOPMENT_SETUP.md): working on the code
- Issues and questions: https://github.com/mbr-crypt/intercat-lynx/issues
