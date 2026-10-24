"""Rate limit: status polling has its own budget and does not use up the general one."""

import pytest

from backend.middleware.redis_rate_limit import (
    STATUS_BUCKET,
    STATUS_PATHS,
    redis_rate_limiter,
)


class _FakePipeline:
    def __init__(self, store):
        self.store, self.keys = store, []

    def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        self.keys.append(self.store[key])

    def expire(self, key, seconds):
        self.keys.append(True)

    def execute(self):
        return self.keys


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def pipeline(self):
        return _FakePipeline(self.store)


@pytest.fixture()
def limiter(monkeypatch):
    monkeypatch.setattr(redis_rate_limiter, "redis_client", _FakeRedis())
    monkeypatch.setattr(redis_rate_limiter, "requests_per_minute", 5)
    monkeypatch.setattr(redis_rate_limiter, "requests_per_hour", 50)
    monkeypatch.setattr(redis_rate_limiter, "status_per_minute", 20)
    monkeypatch.setattr(redis_rate_limiter, "status_per_hour", 200)
    return redis_rate_limiter


def test_status_polling_does_not_use_up_the_general_budget(limiter):
    for _ in range(15):
        assert limiter.check_rate_limit("10.0.0.1", STATUS_BUCKET)[0] is True
    # the general budget of the same address is untouched (login still works)
    for _ in range(5):
        assert limiter.check_rate_limit("10.0.0.1")[0] is True
    assert limiter.check_rate_limit("10.0.0.1")[0] is False


def test_status_bucket_has_its_own_larger_limits(limiter):
    results = [limiter.check_rate_limit("10.0.0.2", STATUS_BUCKET) for _ in range(21)]
    assert all(r[0] for r in results[:20]) and results[20][0] is False
    info = results[0][2]
    assert info["limit_minute"] == 20 and info["limit_hour"] == 200


def test_other_addresses_are_not_affected(limiter):
    for _ in range(6):
        limiter.check_rate_limit("10.0.0.3")
    assert limiter.check_rate_limit("10.0.0.4")[0] is True


def test_only_the_cheap_status_endpoints_are_in_the_status_bucket():
    assert STATUS_PATHS == {"/api/v1/admin/activity", "/api/v1/setup/import/status"}


def test_middleware_sends_activity_polls_to_the_status_bucket(client, limiter):
    # 12 polls would exceed the general limit of 5 per minute
    codes = [client.get("/api/v1/admin/activity").status_code for _ in range(12)]
    assert 429 not in codes  # 401/403 without a token, but not "too many requests"
    # another call of the general kind is still allowed afterwards
    assert client.get("/api/v1/setup/status").status_code == 200
