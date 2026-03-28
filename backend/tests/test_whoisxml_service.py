from datetime import datetime, timedelta, timezone

from services import whoisxml


def test_get_domain_age_days_uses_mock_mapping(monkeypatch) -> None:
    monkeypatch.setenv("WHOIS_MOCK_AGES", "example.com:42")
    assert whoisxml.get_domain_age_days("example.com") == 42


def test_get_domain_age_days_uses_provider_when_configured(monkeypatch) -> None:
    monkeypatch.delenv("WHOIS_MOCK_AGES", raising=False)
    monkeypatch.delenv("WHOIS_CREATED_AT", raising=False)
    monkeypatch.setenv("WHOIS_XML_API_KEY", "test-key")
    monkeypatch.setenv("WHOIS_BASE_URL", "https://whois.example.test")
    monkeypatch.setenv("WHOIS_TIMEOUT_SECONDS", "5")

    created_at = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"WhoisRecord": {"createdDate": created_at}}

    monkeypatch.setattr(whoisxml.httpx, "get", lambda *args, **kwargs: _Response())
    assert whoisxml.get_domain_age_days("example.com") == 45
