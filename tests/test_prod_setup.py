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
        assert https[name] == http[name], f"location differs: {name}"


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
