"""
HYGEIA Compliance Framework — HIPAA, GDPR, CCPA rule enforcement.

Each compliance mode activates additional PII detection rules and
stricter sanitization thresholds. Modes stack: --compliance all
applies the union of all frameworks.
"""

from dataclasses import dataclass, field

HIPAA_18_IDENTIFIERS = [
    "names",
    "geographic_subdivisions",
    "dates",
    "phone_numbers",
    "fax_numbers",
    "email_addresses",
    "ssn",
    "medical_record_numbers",
    "health_plan_beneficiary_numbers",
    "account_numbers",
    "certificate_license_numbers",
    "vehicle_identifiers",
    "device_identifiers",
    "web_urls",
    "ip_addresses",
    "biometric_identifiers",
    "face_photographs",
    "unique_identifying_codes",
]

HIPAA_ADDITIONAL_COLUMNS = {
    "patient_id", "mrn", "medical_record", "health_plan_id",
    "beneficiary_id", "diagnosis", "procedure", "medication",
    "prescription", "fax", "fax_number",
    "vehicle_vin", "vin", "license_plate",
    "device_serial", "serial_number", "device_id", "udid",
    "biometric", "fingerprint", "voiceprint",
    "face_scan", "iris_scan", "face_geometry", "retina_scan",
}

GDPR_SPECIAL_CATEGORY_COLUMNS = {
    "race", "ethnicity", "ethnic_origin", "racial_origin",
    "political_opinion", "political_party", "political_affiliation",
    "religion", "religious_belief", "faith",
    "trade_union", "union_membership",
    "genetic_data", "dna", "genome",
    "biometric_data", "fingerprint", "face_scan", "iris_scan",
    "health_data", "medical_condition", "disability",
    "sexual_orientation", "sex_life", "gender_identity",
}

CCPA_ADDITIONAL_TABLES = {
    "purchase_history", "transactions", "orders", "cart",
    "browsing_history", "search_history", "recent_searches",
    "geolocation", "location_history", "gps_log",
}

CCPA_ADDITIONAL_COLUMNS = {
    "purchase", "transaction", "order_total", "payment",
    "browsing", "search_query", "search_term",
    "geolocation", "location", "gps",
    "biometric_info", "voice_recording", "face_geometry",
    "employment", "employer", "occupation", "salary", "income",
    "education", "school", "university", "degree", "gpa",
    "driver_license", "passport_number",
}


@dataclass
class ComplianceProfile:
    name: str
    extra_sensitive_columns: set = field(default_factory=set)
    extra_pii_tables: set = field(default_factory=set)
    date_generalization: bool = False
    zip_truncation: int = 0
    delete_all_user_content: bool = False
    delete_browsing_history: bool = False


def get_compliance_profile(mode: str) -> ComplianceProfile:
    if mode == "hipaa":
        return ComplianceProfile(
            name="HIPAA Safe Harbor",
            extra_sensitive_columns=HIPAA_ADDITIONAL_COLUMNS,
            date_generalization=True,
            zip_truncation=3,
        )
    elif mode == "gdpr":
        return ComplianceProfile(
            name="GDPR Article 4/9",
            extra_sensitive_columns=GDPR_SPECIAL_CATEGORY_COLUMNS,
            delete_all_user_content=True,
        )
    elif mode == "ccpa":
        return ComplianceProfile(
            name="CCPA",
            extra_sensitive_columns=CCPA_ADDITIONAL_COLUMNS,
            extra_pii_tables=CCPA_ADDITIONAL_TABLES,
            delete_browsing_history=True,
        )
    elif mode == "all":
        hipaa = get_compliance_profile("hipaa")
        gdpr = get_compliance_profile("gdpr")
        ccpa = get_compliance_profile("ccpa")
        return ComplianceProfile(
            name="ALL (HIPAA + GDPR + CCPA)",
            extra_sensitive_columns=(
                hipaa.extra_sensitive_columns |
                gdpr.extra_sensitive_columns |
                ccpa.extra_sensitive_columns
            ),
            extra_pii_tables=ccpa.extra_pii_tables,
            date_generalization=True,
            zip_truncation=3,
            delete_all_user_content=True,
            delete_browsing_history=True,
        )
    else:
        return ComplianceProfile(name="default")


def generate_compliance_report(mode: str, actions: list[dict], verification_passed: bool) -> dict:
    profile = get_compliance_profile(mode)
    report = {
        "compliance_framework": profile.name,
        "mode": mode,
        "verification_passed": verification_passed,
        "identifiers_covered": [],
        "gaps": [],
    }

    action_types = set()
    for a in actions:
        action_types.add(a.get("action", ""))
        for pii in a.get("pii_types_found", []):
            action_types.add(pii)

    if mode in ("hipaa", "all"):
        covered = []
        gaps = []
        checks = [
            ("names", any("sensitive_column:name" in str(a) or "sensitive_column:first_name" in str(a) for a in actions)),
            ("email_addresses", "email" in action_types),
            ("phone_numbers", any("phone" in t for t in action_types)),
            ("ssn", "ssn" in action_types or any("pii_table" in str(a) for a in actions)),
            ("ip_addresses", any("ip" in t for t in action_types)),
            ("web_urls", any("pii_table:top_sites" in str(a) or "pii_table:keyword_search_terms" in str(a) for a in actions)),
            ("account_numbers", any("sensitive_column:account" in str(a) for a in actions)),
            ("device_identifiers", "mac_addr" in action_types or "imei" in action_types),
        ]
        for identifier, is_covered in checks:
            if is_covered:
                covered.append(identifier)
            else:
                gaps.append(identifier)
        report["identifiers_covered"] = covered
        report["gaps"] = gaps

    return report
