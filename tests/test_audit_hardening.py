"""
Regression tests for the findings of the security audit:
public status endpoints, analytics input and the limits on e-mail codes.
"""

import pytest

from backend.models import EmailVerification, UserRole
from backend.security import attempt_limit
from tests.test_setup_api import _admin_token
from tests.test_watchlist import h, make_user, token_of

# ---------------------------------------------------------------------------
# Status endpoints need a role
# ---------------------------------------------------------------------------

STATUS_ENDPOINTS = [
    "/api/v1/tasks/llm-stats",
    "/api/v1/tasks/scheduled/list",
    "/api/v1/tasks/workers/status",
    "/api/v1/tasks/some-task-id",
    "/api/v1/llm/stats",
    "/api/v1/llm/task/some-task-id",
]


@pytest.mark.parametrize("path", STATUS_ENDPOINTS)
def test_status_endpoints_are_not_public(client, path):
    assert client.get(path).status_code in (401, 403)


@pytest.mark.parametrize("path", STATUS_ENDPOINTS)
def test_status_endpoints_are_not_for_plain_viewers(client, db_session, path):
    make_user(db_session, "viewer1", UserRole.VIEWER)
    r = client.get(path, headers=h(token_of(client, "viewer1")))
    assert r.status_code == 403


def test_analysts_pass_the_role_check(client, db_session):
    make_user(db_session, "analyst1", UserRole.ANALYST)
    r = client.get("/api/v1/tasks/scheduled/list", headers=h(token_of(client, "analyst1")))
    assert r.status_code != 403 and r.status_code != 401


# ---------------------------------------------------------------------------
# Analytics input
# ---------------------------------------------------------------------------


class TestAnalytics:
    def track(self, client, **body):
        return client.post("/api/v1/analytics/track", json=body)

    def test_normal_page_view(self, client):
        r = self.track(client, path="/dashboard", visitor_id="3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e")
        assert r.status_code == 200

    def test_path_must_be_a_site_path(self, client):
        assert self.track(client, path="javascript:alert(1)").status_code == 422
        assert self.track(client, path="").status_code == 422

    def test_overlong_path_is_refused(self, client):
        assert self.track(client, path="/" + "a" * 2000).status_code == 422

    def test_odd_visitor_id_is_dropped_not_stored(self, client, db_session):
        from backend.models import PageView

        assert self.track(client, path="/x", visitor_id="<script>alert(1)</script>").status_code == 200
        assert db_session.query(PageView).one().visitor_id is None

    def test_country_header_must_be_a_country_code(self, client, db_session):
        from backend.models import PageView

        client.post(
            "/api/v1/analytics/track",
            json={"path": "/x"},
            headers={"cf-ipcountry": "<b>Xanadu</b>" * 20, "cf-ipcity": "C" * 500},
        )
        row = db_session.query(PageView).one()
        assert row.country is None
        assert len(row.city) == 100

    def test_stats_are_for_administrators_only(self, client, db_session):
        assert client.get("/api/v1/analytics/stats?days=30").status_code in (401, 403)
        make_user(db_session, "viewer2", UserRole.VIEWER)
        r = client.get("/api/v1/analytics/stats?days=30", headers=h(token_of(client, "viewer2")))
        assert r.status_code == 403

    def test_stats_days_are_bounded(self, client, db_session):
        admin = h(_admin_token(client, db_session))
        assert client.get("/api/v1/analytics/stats?days=100000", headers=admin).status_code == 422
        assert client.get("/api/v1/analytics/stats?days=0", headers=admin).status_code == 422
        assert client.get("/api/v1/analytics/stats?days=30", headers=admin).status_code == 200


# ---------------------------------------------------------------------------
# E-mail codes: sending and guessing are limited
# ---------------------------------------------------------------------------


class TestEmailCodes:
    @pytest.fixture(autouse=True)
    def no_real_mail(self, monkeypatch):
        from backend.services.email_service import email_service

        async def fake_send(*args, **kwargs):
            return True

        monkeypatch.setattr(email_service, "send_verification_code", fake_send)

    def send(self, client, email="new@example.org"):
        return client.post("/api/v1/auth/send-verification-code", json={"email": email})

    def verify(self, client, code, email="new@example.org"):
        return client.post("/api/v1/auth/verify-email", json={"email": email, "code": code})

    def test_three_codes_per_address_then_429(self, client):
        for _ in range(3):
            assert self.send(client).status_code == 200
        assert self.send(client).status_code == 429

    def test_other_addresses_are_not_affected_by_one_address(self, client):
        for _ in range(3):
            self.send(client, "a@example.org")
        assert self.send(client, "b@example.org").status_code == 200

    def test_one_client_cannot_flood_many_addresses(self, client):
        for i in range(10):
            assert self.send(client, f"user{i}@example.org").status_code == 200
        assert self.send(client, "user99@example.org").status_code == 429

    def test_five_wrong_codes_lock_further_guesses(self, client):
        self.send(client)
        for _ in range(5):
            assert self.verify(client, "000000").status_code == 400
        assert self.verify(client, "000000").status_code == 429

    def test_right_code_is_also_refused_after_the_limit(self, client, db_session):
        self.send(client)
        real = db_session.query(EmailVerification).one().code
        wrong = "000000" if real != "000000" else "111111"
        for _ in range(5):
            self.verify(client, wrong)
        assert self.verify(client, real).status_code == 429

    def test_right_code_works_before_the_limit(self, client, db_session):
        self.send(client)
        real = db_session.query(EmailVerification).one().code
        self.verify(client, "000000" if real != "000000" else "111111")
        assert self.verify(client, real).status_code == 200

    def test_limiter_counts_expire_with_their_window(self, monkeypatch):
        limiter = attempt_limit.AttemptLimiter("t", 2, 60, "no")
        monkeypatch.setattr(attempt_limit, "USE_REDIS", False)
        limiter.record("k")
        limiter.record("k")
        with pytest.raises(Exception):
            limiter.check("k")
        limiter._memory = {key: (c, 0.0) for key, (c, _) in limiter._memory.items()}
        limiter.check("k")  # window over, no exception


# ---------------------------------------------------------------------------
# Waitlist: the confirmation link belongs to this installation
# ---------------------------------------------------------------------------


class TestWaitlist:
    @pytest.fixture()
    def sent(self, monkeypatch):
        from backend.services.email_service import email_service

        mails = []

        async def fake_send_email(**kwargs):
            mails.append(kwargs)
            return True

        monkeypatch.setattr(email_service, "send_email", fake_send_email)
        return mails

    def test_link_uses_public_url(self, client, sent, monkeypatch):
        monkeypatch.setenv("PUBLIC_URL", "https://lynx.example.org/")
        r = client.post("/api/v1/waitlist/join", json={"email": "someone@example.org"})
        assert r.status_code == 201
        assert "https://lynx.example.org/auth/verify?token=" in sent[0]["text_content"]
        assert "open-threats.com" not in sent[0]["text_content"]

    def test_without_public_url_no_mail_with_foreign_link(self, client, sent, monkeypatch):
        monkeypatch.delenv("PUBLIC_URL", raising=False)
        r = client.post("/api/v1/waitlist/join", json={"email": "someone@example.org"})
        assert r.status_code == 201
        assert sent == []

    def test_signup_mails_are_limited_per_address(self, client, sent, monkeypatch):
        monkeypatch.setenv("PUBLIC_URL", "https://lynx.example.org")
        for _ in range(3):
            client.post("/api/v1/waitlist/join", json={"email": "someone@example.org"})
        r = client.post("/api/v1/waitlist/join", json={"email": "someone@example.org"})
        assert r.status_code == 429
