import httpx
import pytest
import respx

from app.services.leak_check import HIBPNotConfigured, check_leaked_credentials


def test_check_leaked_credentials_requires_api_key(verified_domain, monkeypatch):
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("HIBP_API_KEY", "")
    get_settings.cache_clear()
    try:
        with pytest.raises(HIBPNotConfigured):
            check_leaked_credentials(verified_domain, ["admin@example.com"])
    finally:
        get_settings.cache_clear()


@respx.mock
def test_check_leaked_credentials_reports_breaches(verified_domain, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    get_settings.cache_clear()

    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/admin@example.com").mock(
        return_value=httpx.Response(200, json=[{"Name": "ExampleBreach", "BreachDate": "2023-01-01"}])
    )
    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/clean@example.com").mock(
        return_value=httpx.Response(404)
    )

    try:
        result = check_leaked_credentials(
            verified_domain, ["admin@example.com", "clean@example.com"]
        )
    finally:
        get_settings.cache_clear()

    assert "admin@example.com" in result["breached"]
    assert "clean@example.com" not in result["breached"]
    assert set(result["checked"]) == {"admin@example.com", "clean@example.com"}


@respx.mock
def test_check_leaked_credentials_handles_rate_limit_gracefully(verified_domain, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    get_settings.cache_clear()

    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/rate-limited@example.com").mock(
        return_value=httpx.Response(429)
    )

    try:
        result = check_leaked_credentials(verified_domain, ["rate-limited@example.com"])
    finally:
        get_settings.cache_clear()

    assert result["breached"] == {}
