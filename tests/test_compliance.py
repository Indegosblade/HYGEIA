"""Tests for HIPAA/GDPR/CCPA compliance framework."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.compliance import get_compliance_profile, generate_compliance_report


def test_hipaa_profile():
    p = get_compliance_profile("hipaa")
    assert p.name == "HIPAA Safe Harbor"
    assert "mrn" in p.extra_sensitive_columns
    assert "patient_id" in p.extra_sensitive_columns
    assert "fax" in p.extra_sensitive_columns
    assert "vin" in p.extra_sensitive_columns
    assert p.date_generalization is True
    assert p.zip_truncation == 3


def test_gdpr_profile():
    p = get_compliance_profile("gdpr")
    assert p.name == "GDPR Article 4/9"
    assert "race" in p.extra_sensitive_columns
    assert "ethnicity" in p.extra_sensitive_columns
    assert "religion" in p.extra_sensitive_columns
    assert "sexual_orientation" in p.extra_sensitive_columns
    assert "genetic_data" in p.extra_sensitive_columns
    assert p.delete_all_user_content is True


def test_ccpa_profile():
    p = get_compliance_profile("ccpa")
    assert p.name == "CCPA"
    assert "purchase_history" in p.extra_pii_tables
    assert "geolocation" in p.extra_pii_tables
    assert "employer" in p.extra_sensitive_columns
    assert "salary" in p.extra_sensitive_columns
    assert p.delete_browsing_history is True


def test_all_profile_merges():
    p = get_compliance_profile("all")
    assert "ALL" in p.name
    assert "mrn" in p.extra_sensitive_columns
    assert "race" in p.extra_sensitive_columns
    assert "employer" in p.extra_sensitive_columns
    assert "purchase_history" in p.extra_pii_tables
    assert p.date_generalization is True
    assert p.delete_all_user_content is True
    assert p.delete_browsing_history is True


def test_default_profile():
    p = get_compliance_profile("unknown")
    assert p.name == "default"
    assert len(p.extra_sensitive_columns) == 0
    assert len(p.extra_pii_tables) == 0


def test_compliance_report_structure():
    actions = [
        {"action": "generic_sanitize", "pii_types_found": ["email", "phone_us"]},
        {"action": "generic_sanitize", "pii_types_found": ["sensitive_column:name"]},
    ]
    report = generate_compliance_report("hipaa", actions, verification_passed=True)
    assert report["compliance_framework"] == "HIPAA Safe Harbor"
    assert report["verification_passed"] is True
    assert isinstance(report["identifiers_covered"], list)
    assert isinstance(report["gaps"], list)
    assert "email_addresses" in report["identifiers_covered"]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} — {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
