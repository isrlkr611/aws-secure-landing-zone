from unittest.mock import patch

import dns.exception
import dns.resolver

from app.services import verification


def test_verify_domain_ownership_success(unverified_domain):
    expected_value = unverified_domain.verification_dns_record
    with patch.object(verification, "_lookup_txt_records", return_value=[expected_value]):
        outcome = verification.verify_domain_ownership(unverified_domain)
    assert outcome.verified is True


def test_verify_domain_ownership_wrong_token(unverified_domain):
    with patch.object(verification, "_lookup_txt_records", return_value=["platform-verification=not-the-token"]):
        outcome = verification.verify_domain_ownership(unverified_domain)
    assert outcome.verified is False
    assert "not found" in outcome.detail


def test_verify_domain_ownership_multiple_txt_records(unverified_domain):
    expected_value = unverified_domain.verification_dns_record
    other_records = ["v=spf1 -all", "some-other-service-verification=xyz", expected_value]
    with patch.object(verification, "_lookup_txt_records", return_value=other_records):
        outcome = verification.verify_domain_ownership(unverified_domain)
    assert outcome.verified is True


def test_verify_domain_ownership_nxdomain(unverified_domain):
    with patch.object(verification, "_lookup_txt_records", side_effect=dns.resolver.NXDOMAIN()):
        outcome = verification.verify_domain_ownership(unverified_domain)
    assert outcome.verified is False
    assert "does not exist" in outcome.detail


def test_verify_domain_ownership_no_answer(unverified_domain):
    with patch.object(verification, "_lookup_txt_records", side_effect=dns.resolver.NoAnswer()):
        outcome = verification.verify_domain_ownership(unverified_domain)
    assert outcome.verified is False


def test_verify_domain_ownership_timeout(unverified_domain):
    with patch.object(verification, "_lookup_txt_records", side_effect=dns.exception.Timeout()):
        outcome = verification.verify_domain_ownership(unverified_domain)
    assert outcome.verified is False
    assert "timed out" in outcome.detail


def test_mark_verified_sets_timestamp(unverified_domain):
    assert unverified_domain.is_verified is False
    verification.mark_verified(unverified_domain)
    assert unverified_domain.is_verified is True
    assert unverified_domain.verified_at is not None


def test_require_verified_raises_for_unverified_domain(unverified_domain):
    try:
        verification.require_verified(unverified_domain)
        assert False, "expected PermissionError"
    except PermissionError as exc:
        assert "not verified" in str(exc)


def test_require_verified_passes_for_verified_domain(verified_domain):
    verification.require_verified(verified_domain)  # must not raise


def test_each_domain_gets_a_unique_verification_token(db_session, user_with_key):
    # SQLAlchemy column defaults are applied on flush, not on __init__, so
    # this goes through the session rather than comparing bare constructor
    # output - what matters is that two persisted domains never collide.
    from app.models import Domain

    user, _ = user_with_key
    d1 = Domain(name="a.example.com", owner_id=user.id)
    d2 = Domain(name="b.example.com", owner_id=user.id)
    db_session.add_all([d1, d2])
    db_session.flush()
    assert d1.verification_token != d2.verification_token
