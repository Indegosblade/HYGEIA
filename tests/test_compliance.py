"""Tests for HIPAA/GDPR/CCPA compliance framework."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.compliance import (
    HIPAA_18_IDENTIFIERS,
    generate_compliance_report,
    get_compliance_profile,
)


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


# ---------------------------------------------------------------------------
# Finding #6 — HIPAA report must account for ALL 18 identifiers, not just 8.
# ---------------------------------------------------------------------------

def test_hipaa_report_accounts_for_all_18_identifiers():
    # Empty run: nothing detected. Every one of the 18 Safe Harbor identifiers
    # must still be reported — as a gap (fail closed), never silently omitted.
    report = generate_compliance_report("hipaa", [], verification_passed=False)
    reported = set(report["identifiers_covered"]) | set(report["gaps"])
    missing = set(HIPAA_18_IDENTIFIERS) - reported
    assert not missing, f"HIPAA identifiers silently omitted from report: {missing}"
    assert len(reported & set(HIPAA_18_IDENTIFIERS)) == 18


def test_hipaa_report_previously_omitted_ten_now_appear_as_gaps():
    # These 10 were checked by NEITHER covered nor gaps before the fix.
    previously_omitted = {
        "geographic_subdivisions", "dates", "fax_numbers",
        "medical_record_numbers", "health_plan_beneficiary_numbers",
        "certificate_license_numbers", "vehicle_identifiers",
        "biometric_identifiers", "face_photographs", "unique_identifying_codes",
    }
    report = generate_compliance_report("hipaa", [], verification_passed=False)
    for ident in previously_omitted:
        assert ident in report["gaps"], f"{ident} must be a gap when unverified"


def test_hipaa_report_fax_and_mrn_not_hidden_when_uncaught():
    # Audit scenario: a fax number and MRN sit in a free-text column no handler
    # caught. They must surface as gaps, not vanish from the report.
    actions = [{"action": "generic_sanitize", "pii_types_found": ["email"]}]
    report = generate_compliance_report("hipaa", actions, verification_passed=True)
    assert "fax_numbers" in report["gaps"]
    assert "medical_record_numbers" in report["gaps"]
    assert "email_addresses" in report["identifiers_covered"]


def test_hipaa_report_fax_covered_when_column_redacted():
    actions = [{"action": "generic_sanitize",
                "pii_types_found": ["sensitive_column:fax"]}]
    report = generate_compliance_report("hipaa", actions, verification_passed=True)
    assert "fax_numbers" in report["identifiers_covered"]
    assert "fax_numbers" not in report["gaps"]


# ---------------------------------------------------------------------------
# Finding #28 — gdpr/ccpa must not be empty-but-named.
# ---------------------------------------------------------------------------

def test_gdpr_report_not_empty_but_named():
    report = generate_compliance_report("gdpr", [], verification_passed=True)
    assert "GDPR" in report["compliance_framework"]
    # Before the fix covered AND gaps were both [] -> false assurance.
    assert report["gaps"], "GDPR report must carry identifier-level gaps"
    assert report["limitations"], "GDPR report must state its limitations"


def test_ccpa_report_not_empty_but_named():
    report = generate_compliance_report("ccpa", [], verification_passed=False)
    assert "CCPA" in report["compliance_framework"]
    assert report["gaps"], "CCPA report must carry identifier-level gaps"
    assert report["limitations"]


# ---------------------------------------------------------------------------
# Finding #7 — GDPR/CCPA behavioral flags consumed; column-name-only noted.
# ---------------------------------------------------------------------------

def test_gdpr_special_category_column_marked_covered():
    actions = [{"action": "generic_sanitize",
                "pii_types_found": ["sensitive_column:race",
                                    "sensitive_column:religion"]}]
    report = generate_compliance_report("gdpr", actions, verification_passed=True)
    assert "racial_ethnic_origin" in report["identifiers_covered"]
    assert "religious_philosophical_beliefs" in report["identifiers_covered"]


def test_gdpr_free_text_special_category_is_a_gap_not_a_claim():
    # Audit scenario: a 'body' column holds "I converted to Islam and I'm gay".
    # No special-category column name, no regex -> HYGEIA cannot certify removal.
    # The report must NOT claim coverage and MUST flag the free-text limitation.
    actions = [{"action": "generic_sanitize", "pii_types_found": ["email"]}]
    report = generate_compliance_report("gdpr", actions, verification_passed=True)
    assert "free_text_special_categories" in report["gaps"]
    assert "racial_ethnic_origin" in report["gaps"]
    assert "religious_philosophical_beliefs" in report["gaps"]
    assert "sex_life_or_orientation" in report["gaps"]
    assert any("column-name-based only" in lim for lim in report["limitations"])


def test_gdpr_delete_all_user_content_flag_is_consumed():
    # The formerly-dead flag is now read: surfaced as an explicit gap +
    # limitation rather than silently implying blanket deletion.
    report = generate_compliance_report("gdpr", [], verification_passed=True)
    assert "full_user_content_deletion" in report["gaps"]
    assert any("delete_all_user_content is advisory" in lim
               for lim in report["limitations"])


def test_ccpa_delete_browsing_history_delivered_marks_covered():
    actions = [{"action": "generic_sanitize",
                "pii_types_found": ["pii_table:browsing_history"]}]
    report = generate_compliance_report("ccpa", actions, verification_passed=True)
    assert "browsing_search_history" in report["identifiers_covered"]


def test_ccpa_delete_browsing_history_flag_noted_when_nothing_removed():
    report = generate_compliance_report("ccpa", [], verification_passed=True)
    assert "browsing_search_history" in report["gaps"]
    assert any("delete_browsing_history requested" in lim
               for lim in report["limitations"])


def test_all_mode_report_merges_three_frameworks():
    report = generate_compliance_report("all", [], verification_passed=False)
    reported = set(report["identifiers_covered"]) | set(report["gaps"])
    assert "vehicle_identifiers" in reported       # HIPAA
    assert "racial_ethnic_origin" in reported      # GDPR
    assert "geolocation_data" in reported          # CCPA
    assert "full_user_content_deletion" in report["gaps"]


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
