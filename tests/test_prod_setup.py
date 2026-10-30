"""
Checks for the Docker installation path: compose file, .env template, nginx
configurations, init-env.sh, secret strength and the setup token.

None of this starts Docker. It guards the things that went wrong in the first
test installation (placeholder secrets, files that drifted apart, variables
that only exist in one place).
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from backend.api import setup as setup_api
from backend.models import AppSetting
from backend.security import secret_check

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
NGINX_HTTPS = ROOT / "nginx" / "nginx.conf"
NGINX_HTTP = ROOT / "nginx" / "nginx.http.conf"


# --------------------------------------------------------------------------
# SECRET_KEY strength
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "",
        "short",
        "your-secret-key-here-change-in-production",
        "change-me-in-production-please-use-strong-secret",
        "a" * 40,
        "ChangeMe" + "x7Q" * 12,
    ],
)
def test_weak_secrets_are_rejected(value):
    assert secret_check.weakness(value) != ""


def test_random_secret_is_accepted():
    assert secret_check.weakness("Zr3-k9Qv_LmP2xT8wYc5HbN7dFjA4sGu6EoI1RtK") == ""


def _import_auth(env):
    full = {k: v for k, v in os.environ.items() if k not in ("SECRET_KEY", "ENVIRONMENT")}
    full.update(env)
    full["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, "-c", "import backend.utils.auth"],
        env=full,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_production_refuses_example_secret():
    r = _import_auth(
        {"ENVIRONMENT": "production", "SECRET_KEY": "your-secret-key-here-change-in-production"}
    )
    assert r.returncode != 0
    assert "SECRET_KEY" in r.stderr


def test_production_accepts_random_secret():
    r = _import_auth(
        {"ENVIRONMENT": "production", "SECRET_KEY": "Zr3-k9Qv_LmP2xT8wYc5HbN7dFjA4sGu6EoI1RtK"}
    )
    assert r.returncode == 0, r.stderr


def test_development_only_warns():
    r = _import_auth({"ENVIRONMENT": "development", "SECRET_KEY": "short"})
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------
# Setup token: several processes start at the same moment
# --------------------------------------------------------------------------


def test_setup_token_is_stable(db_session, monkeypatch):
    monkeypatch.delenv("SETUP_TOKEN", raising=False)
    first = setup_api.ensure_token(db_session)
    assert first and setup_api.ensure_token(db_session) == first


def test_setup_token_from_environment_wins(db_session, monkeypatch):
    monkeypatch.setenv("SETUP_TOKEN", "from-env")
    assert setup_api.ensure_token(db_session) == "from-env"
    assert db_session.get(AppSetting, setup_api.TOKEN_KEY) is None


def test_setup_token_race_returns_the_stored_winner(db_session, session_factory, monkeypatch):
    """Another process stores its token between our read and our write."""
    monkeypatch.delenv("SETUP_TOKEN", raising=False)

    other = session_factory()
    try:
        from backend.services import settings_service

        settings_service.set_value(other, setup_api.TOKEN_KEY, "winner-token", secret=True)
    finally:
        other.close()

    real_get = setup_api.settings_service.get
    calls = {"n": 0}

    def get_once_empty(db, key, default=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # we looked before the other process wrote
        return real_get(db, key, default)

    monkeypatch.setattr(setup_api.settings_service, "get", get_once_empty)
    assert setup_api.ensure_token(db_session) == "winner-token"


# --------------------------------------------------------------------------
# docker-compose.yml and .env.example belong together
# --------------------------------------------------------------------------


def _compose():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(COMPOSE.read_text())


def _env_keys(path=ENV_EXAMPLE):
    keys = set()
    for line in path.read_text().splitlines():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if m:
            keys.add(m.group(1))
    return keys


def test_every_compose_variable_is_documented_in_env_example():
    used = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", COMPOSE.read_text()))
    missing = used - _env_keys()
    assert not missing, f"Variables used in docker-compose.yml but missing in .env.example: {sorted(missing)}"


def test_required_values_have_no_default():
    text = COMPOSE.read_text()
    assert "${SECRET_KEY:?" in text
    assert "${POSTGRES_PASSWORD:?" in text
    example = ENV_EXAMPLE.read_text()
    assert re.search(r"^SECRET_KEY=\s*(#.*)?$", example, re.M), "SECRET_KEY must be empty in the template"
    assert re.search(r"^POSTGRES_PASSWORD=\s*(#.*)?$", example, re.M)
    assert "your-secret-key-here" not in example


def test_all_python_services_share_one_environment():
    services = _compose()["services"]
    for name in ("backend", "celery-worker", "celery-beat"):
        env = services[name]["environment"]
        for key in ("SECRET_KEY", "DATABASE_URL", "REDIS_URL", "PUBLIC_URL", "SMTP_HOST"):
            assert key in env, f"{name} lacks {key}"


def test_only_nginx_is_published():
    services = _compose()["services"]
    for name, svc in services.items():
        if name == "nginx":
            continue
        assert "ports" not in svc, f"{name} must not publish ports (TRUSTED_PROXIES assumes nginx is the only way in)"


def test_startup_order_waits_for_healthy_services():
    services = _compose()["services"]
    assert services["backend"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert services["backend"]["depends_on"]["redis"]["condition"] == "service_healthy"
    for name in ("nginx", "celery-worker", "celery-beat"):
        assert services[name]["depends_on"]["backend"]["condition"] == "service_healthy"
    assert "healthcheck" in services["postgres"] and "healthcheck" in services["redis"]


def test_no_fake_healthchecks():
    assert "print('ok')" not in COMPOSE.read_text()
    dockerfile = (ROOT / "Dockerfile.prod").read_text()
    assert "/health/live" in dockerfile
    assert "requests.get" not in dockerfile  # never looked at the status code


def test_frontend_does_not_default_to_a_foreign_api():
    text = (ROOT / "frontend" / "Dockerfile.prod").read_text()
    assert "open-threats.com" not in text and "openthreat.com" not in text
    assert not re.search(r"NEXT_PUBLIC_API_URL=https?://", text)


# --------------------------------------------------------------------------
# nginx: the HTTP and HTTPS variants must stay equal apart from TLS
# --------------------------------------------------------------------------


def _blocks(text, header_re):
    """Return {header: body} for brace blocks whose header matches, nested aware."""
    result = {}
    for m in re.finditer(header_re, text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        body = re.sub(r"#.*", "", text[m.end() : i - 1])
        result[re.sub(r"\s+", " ", m.group(0).strip().rstrip("{").strip())] = re.sub(r"\s+", " ", body).strip()
    return result


def _main_server(path):
    """The server block that carries the application (443 for HTTPS, the only one for HTTP)."""
    text = path.read_text()
    servers = _blocks(text, r"\n\s*server\s*\{")
    for body in servers.values():
        if "location / " in body and "proxy_pass http://frontend" in body:
            return body
    raise AssertionError(f"no application server in {path}")


def _locations(path):
    return _blocks(_main_server(path), r"location\s+[^{]+\{")


def test_nginx_variants_have_identical_locations():
    https, http = _locations(NGINX_HTTPS), _locations(NGINX_HTTP)
    assert set(https) == set(http)
    for name in https:
        # the HTTPS file includes the variant of the header file that adds HSTS
        a = https[name].replace("security-headers-https.conf", "security-headers.conf")
        assert a == http[name], f"location differs: {name}"


def test_nginx_variants_share_upstreams_and_limits():
    for part in (r"upstream\s+\w+\s*\{", r"limit_req_zone[^;]*;"):
        a = _blocks(NGINX_HTTPS.read_text(), part) if "{" in part else set(re.findall(part, NGINX_HTTPS.read_text()))
        b = _blocks(NGINX_HTTP.read_text(), part) if "{" in part else set(re.findall(part, NGINX_HTTP.read_text()))
        assert a == b


@pytest.mark.parametrize("path", [NGINX_HTTPS, NGINX_HTTP])
def test_nginx_never_trusts_client_forwarded_for(path):
    text = path.read_text()
    assert "$proxy_add_x_forwarded_for" not in text
    for line in re.findall(r"proxy_set_header X-Forwarded-For[^;]*;", text):
        assert "$remote_addr" in line


@pytest.mark.parametrize("path", [NGINX_HTTPS, NGINX_HTTP])
def test_nginx_hides_internal_endpoints(path):
    locs = _locations(path)
    for name in ("location = /metrics", "location = /health/detailed"):
        assert "return 404" in locs[name]


def test_http_variant_has_no_tls():
    text = NGINX_HTTP.read_text()
    code = re.sub(r"#.*", "", text)
    assert "ssl_certificate" not in code and "listen 443" not in code
    assert "return 301 https" not in code


def test_https_variant_redirects_but_keeps_health_on_http():
    code = re.sub(r"#.*", "", NGINX_HTTPS.read_text())
    assert "return 301 https://$host$request_uri" in code
    assert "/etc/nginx/ssl/nginx.crt" in code


# --------------------------------------------------------------------------
# scripts/init-env.sh
# --------------------------------------------------------------------------


@pytest.fixture()
def project_copy(tmp_path):
    if not shutil.which("bash") or not shutil.which("awk"):
        pytest.skip("bash/awk not available")
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "init-env.sh", tmp_path / "scripts" / "init-env.sh")
    shutil.copy(ENV_EXAMPLE, tmp_path / ".env.example")
    return tmp_path


def _run(cwd, *args):
    return subprocess.run(
        ["bash", "scripts/init-env.sh", *args], cwd=cwd, capture_output=True, text=True
    )


def _read_env(path):
    values = {}
    for line in (path / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            values[k] = v.split(" #")[0].strip()
    return values


def test_init_env_creates_usable_env(project_copy):
    r = _run(project_copy, "http://10.1.2.3")
    assert r.returncode == 0, r.stderr
    env = _read_env(project_copy)
    assert env["PUBLIC_URL"] == "http://10.1.2.3"
    assert env["ALLOWED_ORIGINS"] == "http://10.1.2.3"
    assert env["NGINX_CONF"] == "./nginx/nginx.http.conf"
    assert secret_check.weakness(env["SECRET_KEY"]) == ""
    assert len(env["POSTGRES_PASSWORD"]) >= 24 and len(env["SETUP_TOKEN"]) >= 24
    assert len({env["SECRET_KEY"], env["POSTGRES_PASSWORD"], env["SETUP_TOKEN"], env["CSRF_SECRET_KEY"]}) == 4
    assert (project_copy / ".env").stat().st_mode & 0o077 == 0, ".env must not be readable by others"
    for secret in (env["SECRET_KEY"], env["POSTGRES_PASSWORD"], env["SETUP_TOKEN"]):
        assert secret not in r.stdout + r.stderr, "secrets must not be printed"
    # the template keys all survive
    assert _env_keys(project_copy / ".env") == _env_keys()


def test_init_env_does_not_overwrite(project_copy):
    assert _run(project_copy, "http://a.example").returncode == 0
    before = (project_copy / ".env").read_text()
    r = _run(project_copy, "http://b.example")
    assert r.returncode != 0
    assert (project_copy / ".env").read_text() == before


def test_init_env_force_keeps_backup(project_copy):
    _run(project_copy, "http://a.example")
    old = (project_copy / ".env").read_text()
    assert _run(project_copy, "http://b.example", "--force").returncode == 0
    assert (project_copy / ".env.bak").read_text() == old
    assert _read_env(project_copy)["PUBLIC_URL"] == "http://b.example"


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")
def test_init_env_https_creates_certificate(project_copy):
    r = _run(project_copy, "https://lynx.example.org", "--https")
    assert r.returncode == 0, r.stderr
    assert _read_env(project_copy)["NGINX_CONF"] == "./nginx/nginx.conf"
    assert (project_copy / "nginx" / "ssl" / "nginx.crt").exists()
    assert (project_copy / "nginx" / "ssl" / "nginx.key").stat().st_mode & 0o077 == 0


# --------------------------------------------------------------------------
# nginx must not hand one user's answer to another (found in the Docker test)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [NGINX_HTTPS, NGINX_HTTP])
def test_nginx_caches_only_public_locations_and_never_with_credentials(path):
    locs = _locations(path)
    cached = {name: body for name, body in locs.items() if "proxy_cache api_cache" in body}
    # exactly the public, read-only locations
    assert set(cached) == {
        "location /api/v1/vulnerabilities",
        "location /api/v1/search",
        "location /api/v1/stats",
    }
    for name, body in cached.items():
        assert "proxy_cache_bypass $skip_cache" in body, name
        assert "proxy_no_cache $skip_cache" in body, name
    # everything personal (auth, watchlist, setup, admin, zabbix) is not cached
    assert "proxy_cache " not in locs["location /api/"]
    code = re.sub(r"#.*", "", path.read_text())
    for header in ("http_authorization", "http_x_setup_token", "http_x_api_key", "http_cookie"):
        assert header in code.split("$skip_cache")[0].split("map ")[-1]


@pytest.mark.skipif(not shutil.which("nginx"), reason="nginx binary not available")
@pytest.mark.parametrize("path", [NGINX_HTTPS, NGINX_HTTP])
def test_nginx_does_not_leak_responses_between_users(path, tmp_path):
    """Real nginx in front of a counting stub: A and B must each get their own answer."""
    import http.server
    import json
    import socket
    import threading
    import time
    import urllib.request

    def free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    calls = {"n": 0}

    class Stub(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            calls["n"] += 1
            body = json.dumps(
                {"call": calls["n"], "who": self.headers.get("Authorization")}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    stub_port, web_port = free_port(), free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", stub_port), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    conf = path.read_text()
    # the shared header files (the HTTPS one includes the plain one by absolute path)
    snippets = tmp_path / "snippets"
    snippets.mkdir()
    for f in (NGINX_HTTPS.parent / "snippets").glob("*.conf"):
        (snippets / f.name).write_text(f.read_text().replace("/etc/nginx/snippets", str(snippets)))
    conf = conf.replace("/etc/nginx/snippets", str(snippets))
    # workers write the cache into tmp_path: run them as the current user
    conf = re.sub(r"(?m)^user nginx;", "user root;" if os.geteuid() == 0 else "", conf)
    conf = conf.replace("/var/run/nginx.pid", str(tmp_path / "nginx.pid"))
    conf = conf.replace("/var/log/nginx/", str(tmp_path) + "/")
    conf = conf.replace("/var/cache/nginx", str(tmp_path / "cache"))
    conf = conf.replace("backend:8001", f"127.0.0.1:{stub_port}")
    conf = conf.replace("frontend:3000", f"127.0.0.1:{stub_port}")
    if "listen 443" in conf:  # HTTPS variant: serve the application server over plain HTTP
        conf = conf.replace("listen 443 ssl;", f"listen {web_port};")
        conf = conf.replace("http2 on;", "")  # needs nginx 1.25.1, the image has it, a local one may not
        conf = re.sub(r"(?m)^\s*ssl_\w+ .*;$", "", conf)
        conf = conf.replace("listen 80;", f"listen {free_port()};")
    else:
        conf = conf.replace("listen 80;", f"listen {web_port};")
    (tmp_path / "cache").mkdir()
    cfg = tmp_path / "nginx.conf"
    cfg.write_text(conf)

    check = subprocess.run(["nginx", "-t", "-c", str(cfg)], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    subprocess.run(["nginx", "-c", str(cfg)], check=True)
    try:
        base = f"http://127.0.0.1:{web_port}"

        def get(url, **headers):
            req = urllib.request.Request(base + url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read()), r.headers.get("X-Cache-Status")

        for _ in range(50):  # wait until nginx accepts connections
            try:
                get("/health")
                break
            except Exception:
                time.sleep(0.1)

        alice, _ = get("/api/v1/auth/me", Authorization="Bearer ALICE")
        bob, _ = get("/api/v1/auth/me", Authorization="Bearer BOB")
        assert alice["who"] == "Bearer ALICE" and bob["who"] == "Bearer BOB"
        assert alice["call"] != bob["call"]

        # personal path without credentials is not cached either
        first, _ = get("/api/v1/setup/status")
        second, _ = get("/api/v1/setup/status")
        assert first["call"] != second["call"]

        # public data is still cached for anonymous visitors, never for logged-in ones
        one, status_one = get("/api/v1/stats")
        two, status_two = get("/api/v1/stats")
        assert one["call"] == two["call"] and status_two == "HIT"
        _, with_auth = get("/api/v1/stats", Authorization="Bearer ALICE")
        assert with_auth == "BYPASS"

        # A location with its own add_header drops every header of the server
        # block. The security headers must still be there everywhere.
        for url in ("/", "/api/v1/stats", "/api/v1/search", "/_next/static/a.js", "/logo.png"):
            with urllib.request.urlopen(base + url, timeout=5) as r:
                for header in ("X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"):
                    assert r.headers.get(header), f"{header} missing on {url}"
    finally:
        subprocess.run(["nginx", "-c", str(cfg), "-s", "stop"], capture_output=True)
        server.shutdown()


def test_init_env_creates_the_ssl_folder_even_without_https(project_copy):
    """Otherwise Docker creates it as root at the first start and the certificate
    for a later HTTPS run cannot be written (found on the VM test)."""
    assert _run(project_copy, "http://10.1.2.3").returncode == 0
    assert (project_copy / "nginx" / "ssl").is_dir()


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not available")
def test_init_env_reports_a_failed_certificate_instead_of_stopping_silently(project_copy, tmp_path_factory):
    real = shutil.which("openssl")
    stub_dir = tmp_path_factory.mktemp("stub")
    stub = stub_dir / "openssl"
    stub.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = req ]; then echo "Can\'t open nginx/ssl/nginx.key for writing: Permission denied" >&2; exit 1; fi\n'
        f'exec {real} "$@"\n'
    )
    stub.chmod(0o755)
    (project_copy / "nginx" / "ssl").mkdir(parents=True)
    (project_copy / "nginx" / "ssl").chmod(0o555)
    import os

    r = subprocess.run(
        ["bash", "scripts/init-env.sh", "https://lynx.example.org", "--https"],
        cwd=project_copy, capture_output=True, text=True,
        env={**os.environ, "PATH": f"{stub_dir}:{os.environ['PATH']}"},
    )
    (project_copy / "nginx" / "ssl").chmod(0o755)
    assert r.returncode != 0
    assert "certificate could not be created" in r.stderr and "Permission denied" in r.stderr
    if os.geteuid() != 0:  # root can always write, so the hint only applies to normal users
        assert "chown" in r.stderr


@pytest.mark.parametrize("path", [NGINX_HTTPS, NGINX_HTTP])
def test_every_location_with_add_header_includes_the_security_headers(path):
    """nginx: add_header in a location replaces ALL inherited add_header lines."""
    wanted = "security-headers-https.conf" if path == NGINX_HTTPS else "security-headers.conf"
    for name, body in _locations(path).items():
        if "add_header" in body:
            assert f"include /etc/nginx/snippets/{wanted}" in body, name


def test_https_server_uses_http2_directive_not_the_listen_parameter():
    """"listen ... http2" is deprecated since nginx 1.25.1 and logs a warning."""
    code = re.sub(r"#.*", "", NGINX_HTTPS.read_text())
    assert "http2 on;" in code
    assert not re.search(r"listen\s+443\s+ssl\s+http2", code)


def test_nginx_is_restarted_together_with_the_services_it_proxies():
    """nginx resolves backend/frontend once at start; without this the site shows
    "gleich geht es weiter" after every `docker compose up -d --build`."""
    depends = _compose()["services"]["nginx"]["depends_on"]
    for name in ("backend", "frontend"):
        assert depends[name].get("restart") is True, name
