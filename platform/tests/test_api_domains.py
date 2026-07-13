from unittest.mock import patch

from app.services import verification


def test_register_returns_api_key_once(client):
    response = client.post("/auth/register", json={"email": "new-user@example.com"})
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new-user@example.com"
    assert len(body["api_key"]) > 20


def test_register_duplicate_email_conflicts(client):
    client.post("/auth/register", json={"email": "dup@example.com"})
    response = client.post("/auth/register", json={"email": "dup@example.com"})
    assert response.status_code == 409


def test_domains_endpoints_require_api_key(client):
    response = client.get("/domains")
    assert response.status_code == 401


def test_add_domain_returns_verification_instructions(client, auth_headers):
    response = client.post("/domains", json={"name": "example.com"}, headers=auth_headers)
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "example.com"
    assert body["dns_record_value"].startswith("platform-verification=")
    assert "verify" in body["instructions"]


def test_cannot_register_the_same_domain_twice(client, auth_headers):
    client.post("/domains", json={"name": "example.com"}, headers=auth_headers)
    response = client.post("/domains", json={"name": "example.com"}, headers=auth_headers)
    assert response.status_code == 409


def test_scan_on_unverified_domain_is_blocked_not_silently_skipped(client, auth_headers):
    client.post("/domains", json={"name": "example.com"}, headers=auth_headers)

    domains = client.get("/domains", headers=auth_headers).json()
    domain_id = domains[0]["id"]
    assert domains[0]["is_verified"] is False

    scan_response = client.post(f"/domains/{domain_id}/scan/tls", headers=auth_headers)
    assert scan_response.status_code == 201
    scan_body = scan_response.json()
    # The attempt is recorded, auditable, and explicitly marked blocked -
    # NOT silently dropped and NOT run against the target.
    assert scan_body["status"] == "blocked_unverified"


def test_verify_endpoint_rejects_when_txt_record_absent(client, auth_headers):
    client.post("/domains", json={"name": "example.com"}, headers=auth_headers)
    domain_id = client.get("/domains", headers=auth_headers).json()[0]["id"]

    with patch.object(verification, "_lookup_txt_records", return_value=["v=spf1 -all"]):
        response = client.post(f"/domains/{domain_id}/verify", headers=auth_headers)

    # Proves the endpoint doesn't just trust the client - it re-checks DNS
    # and refuses to flip is_verified without the exact expected TXT value.
    assert response.status_code == 200
    assert response.json()["verified"] is False
    assert client.get(f"/domains/{domain_id}", headers=auth_headers).json()["is_verified"] is False


def test_verify_endpoint_marks_domain_verified_on_success(client, auth_headers, db_session):
    from app.models import Domain

    client.post("/domains", json={"name": "example.com"}, headers=auth_headers)
    domain = db_session.query(Domain).filter(Domain.name == "example.com").first()
    expected_value = domain.verification_dns_record

    with patch.object(verification, "_lookup_txt_records", return_value=[expected_value]):
        response = client.post(f"/domains/{domain.id}/verify", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["verified"] is True
    assert client.get(f"/domains/{domain.id}", headers=auth_headers).json()["is_verified"] is True


def test_trigger_scan_runs_and_persists_result_for_verified_domain(client, auth_headers, db_session):
    from app.models import Domain

    client.post("/domains", json={"name": "example.com"}, headers=auth_headers)
    domain = db_session.query(Domain).filter(Domain.name == "example.com").first()
    verification.mark_verified(domain)
    db_session.add(domain)
    db_session.commit()

    fake_result = {
        "hostname": "example.com",
        "port": 443,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "days_remaining": 1500,
        "expiring_soon": False,
    }
    with patch("app.services.scan_runner.tls_check.check_certificate", return_value=fake_result):
        response = client.post(f"/domains/{domain.id}/scan/tls", headers=auth_headers)

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "success"
    assert body["data"]["days_remaining"] == 1500
