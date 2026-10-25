# Nginx Configuration

This directory contains three nginx configurations:

## 📁 Files

- **`nginx.http.conf`** - Production configuration **without HTTPS**. This is what `docker-compose.yml` uses by default: a first test works without certificates. Also right when another proxy in front terminates TLS.
- **`nginx.conf`** - Production configuration **with HTTPS** and a redirect from port 80. Needs `nginx/ssl/nginx.crt` and `nginx/ssl/nginx.key`.
- **`nginx.dev.conf`** - Development configuration (without HTTPS, relaxed rate limits, `host.docker.internal` instead of container names)

Which production file is used is chosen by `NGINX_CONF` in `.env` (see `.env.example`). `nginx.http.conf` and `nginx.conf` must stay identical apart from the TLS parts; `tests/test_prod_setup.py` fails when their routes, limits or upstreams drift apart. Change both together.

### What the production files guarantee

- `/api/*` goes to the backend, everything else to the frontend.
- `X-Forwarded-For` is **replaced** by the real client address (never appended to what the client sent). The backend trusts exactly this (`TRUSTED_PROXIES=1`) for rate limits and login lockouts.
- `/metrics` and `/health/detailed` answer 404 from outside. Prometheus reads them directly from `backend:8001` inside the Docker network.
- Upstream names (`backend`, `frontend`) are resolved when nginx starts. After recreating the backend container run `docker compose restart nginx`, otherwise nginx may keep the old address.

## 🚀 Local Testing

### Option 1: Next.js Rewrites (Recommended for Development)

The easiest method is to use Next.js Rewrites. These are already configured in `frontend/next.config.js`.

**Prerequisites:**
- Backend running on `http://127.0.0.1:8001`
- Frontend running on `http://localhost:3000`

**Start:**
```bash
# Terminal 1: Start backend (from the project root, not from backend/)
python -m uvicorn backend.main:app --reload --port 8001

# Terminal 2: Start frontend
cd frontend
npm run dev
```

**Test:**
- Frontend: http://localhost:3000
- API calls are automatically forwarded to http://127.0.0.1:8001

### Option 2: Nginx locally with Docker

If you want to replicate the complete production environment locally:

**1. Docker Compose with nginx.dev.conf:**

Create a `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    container_name: openthreat-nginx-dev
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.dev.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - backend
      - frontend
    networks:
      - openthreat-network
    extra_hosts:
      - "host.docker.internal:host-gateway"

  backend:
    # ... your backend configuration
    
  frontend:
    # ... your frontend configuration

networks:
  openthreat-network:
    driver: bridge
```

**2. Start:**
```bash
docker-compose -f docker-compose.dev.yml up
```

**3. Test:**
- Everything via nginx: http://localhost

## 🔒 Production Deployment

In production, `nginx.conf` is used, which provides the following features:

- ✅ HTTPS with TLS 1.2/1.3
- ✅ Strict rate limits
- ✅ Security headers (CSP, HSTS, etc.)
- ✅ Caching for API responses
- ✅ Compression (gzip)

**Important:** The `nginx.conf` is optimized for production and should not be used locally because it:
- Expects HTTPS certificates
- Redirects HTTP to HTTPS
- Has stricter rate limits

## 🔄 Differences between dev and prod

| Feature | Development (`nginx.dev.conf`) | Production (`nginx.conf`) |
|---------|-------------------------------|---------------------------|
| HTTPS | ❌ No (HTTP only) | ✅ Yes (with redirect) |
| Rate Limits | 🟢 Relaxed (50-100 req/s) | 🔴 Strict (2-20 req/s) |
| Caching | ❌ Disabled | ✅ Enabled |
| SSL/TLS | ❌ Not configured | ✅ TLS 1.2/1.3 |
| Security Headers | ⚠️ Minimal | ✅ Full (CSP, HSTS) |
| Upstream | `host.docker.internal` | `backend:8001`, `frontend:3000` |

## 📝 Customizations

### Change Backend Port

If your backend runs on a different port:

**In `next.config.js`:**
```javascript
destination: 'http://127.0.0.1:YOUR_PORT/api/:path*',
```

**In `nginx.dev.conf`:**
```nginx
upstream backend {
    server host.docker.internal:YOUR_PORT;
}
```

### Change Frontend Port

**In `nginx.dev.conf`:**
```nginx
upstream frontend {
    server host.docker.internal:YOUR_PORT;
}
```

## 🔒 Security headers

`snippets/security-headers.conf` (and `security-headers-https.conf`, which adds HSTS) hold the security headers
once. They are mounted into the nginx container at `/etc/nginx/snippets`. Every `location` that sets its own
`add_header` has to include the file again: nginx drops all inherited `add_header` lines as soon as a location
defines one. A test (`tests/test_prod_setup.py`) checks this.

## 🐛 Troubleshooting

### Problem: the page says "Gleich geht es weiter" after an update

That is the friendly error page of nginx (it answers 502/503/504 while the backend is not reachable) and it
reloads itself every 10 seconds. During `docker compose up -d --build` it is normal for a minute or two: the
backend containers are replaced one after the other and need a few seconds to pass their health check.

If it stays longer than two minutes:

```bash
docker compose ps                  # is the backend "healthy"?
docker compose logs --tail 50 backend
docker compose restart nginx       # nginx looks up the container addresses once at start;
                                   # after the backend got a new address it has to look again
```

### Problem: "502 Bad Gateway" in nginx

**Solution:** Make sure backend and frontend are running:
```bash
# Test backend
curl http://127.0.0.1:8001/health

# Test frontend
curl http://localhost:3000
```

### Problem: API calls don't work locally

**Solution 1:** Make sure the Next.js dev server was restarted after changes to `next.config.js`:
```bash
cd frontend
npm run dev
```

**Solution 2:** Check the browser console for CORS errors. Next.js Rewrites should avoid CORS issues.

### Problem: "host.docker.internal" not reachable

**Solution:** On Linux, you must add `extra_hosts` to docker-compose:
```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

## 📚 Further Information

- [Next.js Rewrites Documentation](https://nextjs.org/docs/api-reference/next.config.js/rewrites)
- [Nginx Reverse Proxy Guide](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)
