# 🚀 Production Deployment Guide

> **Installing?** Use [QUICK_START.md](../QUICK_START.md). It describes the tested path (`./scripts/init-env.sh`, `docker compose up -d --build`). This page is background material from the original project about protecting a public instance against abuse (rate limits, caching, DDoS); its configuration examples may differ from the files in this repository. When in doubt, `docker-compose.yml` and `nginx/` are authoritative.

## 🎯 Deployment-Strategie gegen Missbrauch

### Problem: API-Missbrauch & Hohe Kosten

**Risiken:**
- ❌ DDoS-Attacken → Server-Überlastung
- ❌ API-Scraping → Hohe Bandbreite
- ❌ Datenbank-Overload → Langsame Queries
- ❌ Hohe Cloud-Kosten → $$$

**Lösung: Multi-Layer Protection** ✅

---

## 🛡️ Schutz-Strategie (Multi-Layer)

### Layer 1: CDN & DDoS Protection (Cloudflare)
### Layer 2: Rate Limiting (Redis)
### Layer 3: Caching (Redis + CDN)
### Layer 4: Database Optimization
### Layer 5: Cost Monitoring

---

## 💰 Empfohlene Deployment-Option

### **Option: Hetzner Cloud + Cloudflare** ⭐ BESTE PREIS/LEISTUNG

**Warum?**
- ✅ **Günstig:** ~20-40€/Monat (statt $100+ bei AWS)
- ✅ **DDoS-Schutz:** Cloudflare Free Plan
- ✅ **Unbegrenzte Bandbreite:** Hetzner inkludiert
- ✅ **EU-Server:** DSGVO-konform
- ✅ **Skalierbar:** Einfaches Upgrade

---

## 🏗️ Architektur

```
Internet
   │
   ▼
┌─────────────────────────────────────┐
│   Cloudflare (Free Plan)            │
│   - DDoS Protection                 │
│   - CDN Caching                     │
│   - Rate Limiting (10k req/day)     │
│   - SSL/TLS                         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Hetzner Cloud VPS                 │
│   CPX21: 3 vCPU, 4GB RAM, 80GB SSD │
│   ~8€/Monat                         │
│                                     │
│   ┌─────────────────────────────┐  │
│   │   Nginx (Reverse Proxy)     │  │
│   │   - Rate Limiting           │  │
│   │   - Caching                 │  │
│   │   - Compression             │  │
│   └──────────┬──────────────────┘  │
│              │                      │
│   ┌──────────▼──────────────────┐  │
│   │   Docker Containers         │  │
│   │                             │  │
│   │   ┌─────────────────────┐  │  │
│   │   │  Frontend (Next.js) │  │  │
│   │   │  Port 3000          │  │  │
│   │   └─────────────────────┘  │  │
│   │                             │  │
│   │   ┌─────────────────────┐  │  │
│   │   │  Backend (FastAPI)  │  │  │
│   │   │  Port 8001          │  │  │
│   │   └─────────────────────┘  │  │
│   │                             │  │
│   │   ┌─────────────────────┐  │  │
│   │   │  PostgreSQL         │  │  │
│   │   │  Port 5432          │  │  │
│   │   └─────────────────────┘  │  │
│   │                             │  │
│   │   ┌─────────────────────┐  │  │
│   │   │  Redis              │  │  │
│   │   │  Port 6379          │  │  │
│   │   └─────────────────────┘  │  │
│   └─────────────────────────────┘  │
└─────────────────────────────────────┘
```

---

## 🔒 Rate Limiting Strategie

### Cloudflare (Layer 1)
```
- 10,000 requests/day (Free Plan)
- Automatischer DDoS-Schutz
- Bot-Erkennung
```

### Nginx (Layer 2)
```nginx
# /etc/nginx/nginx.conf

limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;

server {
    location /api/v1/vulnerabilities {
        limit_req zone=api burst=20 nodelay;
    }
    
    location /api/v1/search {
        limit_req zone=search burst=10 nodelay;
    }
}
```

### Redis (Layer 3 - Application Level)
```python
# Bereits implementiert in backend/middleware/rate_limit.py
- 10 requests/second per IP
- 60 requests/minute per IP
- 1000 requests/hour per IP
- 10000 requests/day per IP
```

---

## 💾 Caching-Strategie

### 1. Cloudflare CDN Cache
```
- Static Assets: 1 Jahr
- API Responses: 5 Minuten
- HTML: 1 Stunde
```

### 2. Redis Application Cache
```python
# Cache häufige Queries
- /api/v1/stats → 5 Minuten
- /api/v1/vulnerabilities (ohne Filter) → 2 Minuten
- /api/v1/search (gleiche Query) → 1 Minute
```

### 3. Database Query Cache
```sql
-- PostgreSQL Shared Buffers
shared_buffers = 1GB
effective_cache_size = 3GB
```

---

## 📦 Docker Production Setup

### docker-compose.prod.yml

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/cache:/var/cache/nginx
    depends_on:
      - frontend
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    environment:
      - NODE_ENV=production
      - NEXT_PUBLIC_API_URL=https://api.openthreat.io
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M

  backend:
    build:
      context: .
      dockerfile: Dockerfile.prod
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/openthreat
      - REDIS_URL=redis://redis:6379
      - LOG_LEVEL=INFO
      - RATE_LIMIT_ENABLED=true
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
      replicas: 2  # Load balancing

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=openthreat
      - POSTGRES_USER=openthreat
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
    command: >
      postgres
      -c shared_buffers=512MB
      -c effective_cache_size=1536MB
      -c maintenance_work_mem=128MB
      -c max_connections=100

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

  celery-worker:
    build:
      context: .
      dockerfile: Dockerfile.prod
    command: celery -A backend.celery_app worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/openthreat
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

  celery-beat:
    build:
      context: .
      dockerfile: Dockerfile.prod
    command: celery -A backend.celery_app beat --loglevel=info
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/openthreat
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 256M

volumes:
  postgres_data:
  redis_data:
```

---

## 🔐 Nginx Configuration

### /nginx/nginx.conf

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;

    # Rate Limiting Zones
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;
    limit_req_zone $binary_remote_addr zone=stats:10m rate=2r/s;

    # Cache
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m 
                     max_size=1g inactive=60m use_temp_path=off;

    upstream backend {
        least_conn;
        server backend:8001 max_fails=3 fail_timeout=30s;
    }

    upstream frontend {
        server frontend:3000;
    }

    server {
        listen 80;
        server_name openthreat.io www.openthreat.io;

        # Security Headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;

        # API Endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            limit_req_status 429;

            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Cache GET requests
            proxy_cache api_cache;
            proxy_cache_methods GET;
            proxy_cache_valid 200 5m;
            proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
            add_header X-Cache-Status $upstream_cache_status;
        }

        # Search Endpoint (stricter limit)
        location /api/v1/search {
            limit_req zone=search burst=10 nodelay;
            limit_req_status 429;

            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            # Cache search results
            proxy_cache api_cache;
            proxy_cache_valid 200 1m;
        }

        # Stats Endpoint (very strict)
        location /api/v1/stats {
            limit_req zone=stats burst=5 nodelay;
            
            proxy_pass http://backend;
            proxy_cache api_cache;
            proxy_cache_valid 200 5m;
        }

        # Frontend
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Static files (aggressive caching)
        location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
            proxy_pass http://frontend;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

---

## 💰 Kosten-Kalkulation

### Hetzner Cloud Setup

| Service | Specs | Kosten/Monat |
|---------|-------|--------------|
| **VPS CPX21** | 3 vCPU, 4GB RAM, 80GB SSD | 8,21€ |
| **Backup** | Automatische Backups | 1,64€ |
| **Volume** | 100GB zusätzlich (optional) | 4,90€ |
| **Cloudflare** | Free Plan | 0€ |
| **Domain** | .io Domain | ~3€ |
| **TOTAL** | | **~18€/Monat** |

### Skalierung bei Wachstum

| Traffic | VPS | Kosten |
|---------|-----|--------|
| <10k Users/Tag | CPX21 (4GB) | 8€ |
| 10-50k Users/Tag | CPX31 (8GB) | 16€ |
| 50-100k Users/Tag | CPX41 (16GB) | 31€ |
| >100k Users/Tag | Load Balancer + 2x CPX31 | 45€ |

---

## 🚀 Deployment Steps

### 1. Hetzner Server Setup

```bash
# SSH in Server
ssh root@your-server-ip

# Update System
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
apt install docker-compose-plugin -y

# Create user
adduser openthreat
usermod -aG docker openthreat
su - openthreat
```

### 2. Deploy Application

```bash
# Clone Repository
git clone https://github.com/hoodinformatik/OpenThreat.git
cd OpenThreat

# Setup Environment
cp .env.example .env
nano .env  # Configure DATABASE_URL, REDIS_URL, etc.

# Build and Start
docker-compose -f docker-compose.prod.yml up -d

# Check Status
docker-compose ps
docker-compose logs -f
```

### 3. Cloudflare Setup

1. **Domain zu Cloudflare hinzufügen**
2. **DNS Records:**
   ```
   A    @    your-server-ip
   A    www  your-server-ip
   ```
3. **SSL/TLS:** Full (strict)
4. **Firewall Rules:**
   - Block countries (optional)
   - Challenge on high threat score
5. **Rate Limiting:**
   - 10,000 requests/day per IP
6. **Caching:**
   - Cache Everything für `/api/v1/stats`
   - Cache für 5 Minuten

---

## 📊 Monitoring & Alerts

### 1. Uptime Monitoring (UptimeRobot - Free)

```
https://uptimerobot.com
- Monitor: https://openthreat.io/health
- Interval: 5 Minuten
- Alert: Email bei Ausfall
```

### 2. Cost Monitoring

```bash
# Hetzner Cloud Console
- Set Budget Alert: 50€/Monat
- Email bei 80% Budget
```

### 3. Application Monitoring

```bash
# Prometheus + Grafana (bereits implementiert)
docker-compose -f docker-compose.monitoring.yml up -d

# Access Grafana
http://your-server-ip:3001
```

---

## 🛡️ Security Checklist

- [ ] Firewall aktiviert (UFW)
- [ ] SSH Key-only Authentication
- [ ] Fail2ban installiert
- [ ] Automatische Security Updates
- [ ] Database Backups (täglich)
- [ ] SSL/TLS via Cloudflare
- [ ] Rate Limiting auf allen Ebenen
- [ ] Secrets in Environment Variables
- [ ] Docker Container als non-root User
- [ ] Log Rotation konfiguriert

---

## 🔥 Emergency Procedures

### Bei DDoS-Attacke:

1. **Cloudflare "Under Attack Mode"** aktivieren
2. **Nginx Rate Limits** verschärfen
3. **Temporär API deaktivieren** (nur Frontend)
4. **Logs analysieren** für Attack Pattern

### Bei hoher Last:

1. **Caching erhöhen** (TTL von 5min auf 15min)
2. **Database Connection Pool** erhöhen
3. **Horizontal skalieren** (2. Backend Container)
4. **CDN für Static Assets** aktivieren

---

## 📈 Performance Optimierung

### Database Indexes

```sql
-- Bereits vorhanden, aber prüfen:
CREATE INDEX idx_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_severity ON vulnerabilities(severity);
CREATE INDEX idx_exploited ON vulnerabilities(exploited_in_the_wild);
CREATE INDEX idx_published ON vulnerabilities(published_at DESC);
```

### Redis Caching

```python
# In backend/api/stats.py
@router.get("/stats")
@cache(expire=300)  # 5 Minuten Cache
async def get_stats():
    ...
```

---

## ✅ Go-Live Checklist

- [ ] Domain konfiguriert
- [ ] SSL/TLS aktiv
- [ ] Cloudflare aktiviert
- [ ] Rate Limiting getestet
- [ ] Backups konfiguriert
- [ ] Monitoring aktiv
- [ ] Logs rotieren
- [ ] Security Headers gesetzt
- [ ] Performance getestet
- [ ] Documentation aktualisiert

---

## 📧 Support

Bei Fragen:
- **Email:** hoodinformatik@gmail.com
- **GitHub:** https://github.com/hoodinformatik/OpenThreat

---

**Geschätzte Kosten:** ~18€/Monat
**Schutz:** Multi-Layer (Cloudflare + Nginx + Redis)
**Skalierung:** Bis 100k Users/Tag möglich
**Uptime:** 99.9% mit Cloudflare

🎉 **Production-Ready Deployment!**
