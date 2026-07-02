"""
HYGEIA Compliance Framework — HIPAA, GDPR, CCPA rule enforcement.

Each compliance mode activates additional PII detection rules and
stricter sanitization thresholds. Modes stack: --compliance all
applies the union of all frameworks.

Honesty over assurance (findings #5/#6/#7/#28)
----------------------------------------------
The printed framework name is only ever a *label*. What HYGEIA actually
delivers is reported per-run as ``identifiers_covered`` / ``gaps`` /
``limitations`` so the claim can never outrun the behavior:

* HIPAA Safe Harbor requires date elements be generalized to the year and ZIP
  codes truncated to 3 digits (000 for low-population prefixes). Those
  transforms are implemented here as :func:`generalize_date` /
  :func:`truncate_zip` and exposed via :meth:`ComplianceProfile.transform_value`
  (the single wiring point that honors ``date_generalization`` /
  ``zip_truncation``). Where the running pipeline only redacts date/ZIP *columns*
  by name — and never touches free-text dates/ZIPs — ``dates`` and
  ``geographic_subdivisions`` are reported at column level and the residual gap
  is spelled out in ``limitations``.
* All 18 Safe Harbor identifiers are evaluated. An identifier is ``covered``
  only with positive evidence in the run's actions; otherwise it is a ``gap``
  (fail closed — absence of evidence is never silently treated as removed).
* GDPR/CCPA now produce identifier-level coverage/gaps too, and the
  ``delete_all_user_content`` / ``delete_browsing_history`` flags are read (no
  longer dead). Special-category detection is column-name-based only; that limit
  is stated explicitly rather than implied away by a bare framework name.
"""

import re
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


# ---------------------------------------------------------------------------
# HIPAA Safe Harbor generalization helpers (finding #5)
# ---------------------------------------------------------------------------

# 45 CFR 164.514(b)(2): the initial three digits of a ZIP code must be changed
# to 000 when the 3-digit prefix covers 20,000 or fewer people. This is the
# canonical HHS list (2000 census). Any prefix here generalizes to "000".
RESTRICTED_ZIP3 = frozenset({
    "036", "059", "063", "102", "203", "556", "692", "790",
    "821", "823", "830", "831", "878", "879", "884", "890", "893",
})

# Column names whose values are ZIP codes / dates for transform_value().
_ZIP_COLUMN_NAMES = {
    "zip", "zipcode", "zip_code", "postal_code", "postalcode", "postal",
}
_DATE_COLUMN_NAMES = {
    "date", "date_of_birth", "dob", "birthdate", "birthday", "birth_date",
    "admission_date", "discharge_date", "encounter_date", "service_date",
    "visit_date", "appointment_date", "death_date", "date_of_death",
}


def truncate_zip(value):
    """HIPAA Safe Harbor ZIP generalization: keep only the first 3 digits, or
    ``"000"`` for restricted low-population prefixes.

    Fail closed: if the value carries no 3-digit run that could form a ZIP3, the
    maximally-generalized ``"000"`` is returned rather than passing the original
    (possibly full ZIP) through — a helper that claims to de-identify must never
    leak the value it was handed.
    """
    if value is None:
        return value
    text = str(value)
    m = re.search(r"\d{3,}", text)
    if not m:
        return "000"
    prefix = m.group(0)[:3]
    if prefix in RESTRICTED_ZIP3:
        return "000"
    return prefix


def generalize_date(value):
    """HIPAA Safe Harbor date generalization: reduce a date to its 4-digit year.

    Handles ISO (``2019-03-14``), US (``03/14/2019``), textual
    (``March 15, 1985``), dotted (``14.03.2019``) and compact 8-digit
    (``20190314`` / ``03142019``) forms.

    Fail closed: if no plausible 4-digit year can be extracted the value is
    replaced with ``"[REDACTED]"`` — never returned with month/day intact — so a
    date that cannot be safely generalized is removed rather than leaked.
    """
    if value is None:
        return value
    text = str(value)
    m = re.search(r"(?<!\d)((?:19|20)\d{2})(?!\d)", text)
    if m:
        return m.group(1)
    digits = re.sub(r"\D", "", text)
    if len(digits) == 8:
        for cand in (digits[:4], digits[4:]):
            if cand[:2] in ("19", "20"):
                return cand
    return "[REDACTED]"


@dataclass
class ComplianceProfile:
    name: str
    extra_sensitive_columns: set = field(default_factory=set)
    extra_pii_tables: set = field(default_factory=set)
    date_generalization: bool = False
    zip_truncation: int = 0
    delete_all_user_content: bool = False
    delete_browsing_history: bool = False

    def transform_value(self, column_name, value):
        """Apply Safe-Harbor generalization to a single cell value.

        This is the one place a pipeline should call to *honor* the
        ``date_generalization`` / ``zip_truncation`` flags (finding #5): a ZIP
        column is truncated to 3 digits and a date column is generalized to its
        year when the profile enables it. All other columns pass through
        unchanged. Returns the (possibly) transformed value.
        """
        if value is None:
            return value
        col = (column_name or "").lower()
        if self.zip_truncation and col in _ZIP_COLUMN_NAMES:
            return truncate_zip(value)
        if self.date_generalization and col in _DATE_COLUMN_NAMES:
            return generalize_date(value)
        return value


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


# ---------------------------------------------------------------------------
# Coverage evidence maps (findings #6/#7/#28)
#
# Each identifier maps to the evidence that would prove it was addressed in a
# run. Evidence is drawn from the sanitizer's ``pii_types_found`` entries:
#   * "sensitive_column:<name>"  -> redacted column (matched against ``cols``)
#   * "pii_table:<name>"         -> nuked table    (matched against ``tables``)
#   * "<regex_name>"             -> regex hit      (matched against ``types`` /
#                                                   ``type_prefixes``)
# plus the action name itself (matched against ``actions``). Absence of any
# such evidence => the identifier is reported as a GAP (fail closed).
# ---------------------------------------------------------------------------

_HIPAA_EVIDENCE = {
    "names": {"cols": {"name", "first_name", "last_name", "full_name",
                       "firstname", "lastname", "fullname", "display_name",
                       "nickname", "given_name", "family_name"}},
    "geographic_subdivisions": {
        "cols": {"address", "street", "street_address", "city", "zip",
                 "zipcode", "zip_code", "postal_code", "state", "country",
                 "address_line_1", "address_line_2"},
        "actions": {"zip_truncated"}},
    "dates": {"cols": {"date_of_birth", "dob", "birthdate", "birthday"},
              "types": {"date_of_birth"}, "actions": {"date_generalized"}},
    "phone_numbers": {"cols": {"phone", "phone_number", "mobile", "cell"},
                      "type_prefixes": ("phone",)},
    "fax_numbers": {"cols": {"fax", "fax_number"}},
    "email_addresses": {"cols": {"email"}, "types": {"email", "apple_id"}},
    "ssn": {"cols": {"ssn", "social_security"}, "types": {"ssn"}},
    "medical_record_numbers": {"cols": {"mrn", "medical_record", "patient_id"}},
    "health_plan_beneficiary_numbers": {
        "cols": {"health_plan_id", "beneficiary_id", "member_id", "subscriber_id"}},
    "account_numbers": {"cols": {"account", "account_number", "bank_account"}},
    "certificate_license_numbers": {
        "cols": {"license_number", "drivers_license", "license",
                 "passport", "passport_number"},
        "types": {"drivers_license", "us_passport"}},
    "vehicle_identifiers": {"cols": {"vin", "vehicle_vin", "license_plate"},
                            "types": {"vin", "uk_plate"}},
    "device_identifiers": {
        "cols": {"serial_number", "device_serial", "device_id", "device_udid",
                 "udid", "imei", "imsi", "iccid", "meid"},
        "types": {"imei", "imsi", "mac_addr", "device_name"}},
    "web_urls": {"tables": {"top_sites", "keyword_search_terms",
                            "history_items", "history_visits", "browsing_history"},
                 "types": {"url_credentials"}},
    "ip_addresses": {"cols": {"ip_address", "ipaddr", "remote_addr"},
                     "type_prefixes": ("ip_v",)},
    "biometric_identifiers": {
        "cols": {"biometric", "fingerprint", "voiceprint", "iris_scan",
                 "retina_scan", "face_geometry", "genetic_data", "dna"}},
    "face_photographs": {"cols": {"face_data", "face_scan", "face_geometry"},
                         "tables": {"zdetectedface", "zdetectedfaceprint",
                                    "zsceneprint"},
                         "actions": {"exif_strip"}},
    "unique_identifying_codes": {
        "types": {"npi", "dea_number", "medicare_mbi", "ndc"},
        "cols": {"udid"}},
}

_GDPR_EVIDENCE = {
    "racial_ethnic_origin": {"cols": {"race", "ethnicity", "ethnic_origin",
                                      "racial_origin"}},
    "political_opinions": {"cols": {"political_opinion", "political_party",
                                    "political_affiliation"}},
    "religious_philosophical_beliefs": {"cols": {"religion", "religious_belief",
                                                 "faith"}},
    "trade_union_membership": {"cols": {"trade_union", "union_membership"}},
    "genetic_data": {"cols": {"genetic_data", "dna", "genome"}},
    "biometric_data": {"cols": {"biometric_data", "biometric", "fingerprint",
                                "face_scan", "iris_scan"}},
    "health_data": {"cols": {"health_data", "medical_condition", "disability",
                             "diagnosis"}},
    "sex_life_or_orientation": {"cols": {"sexual_orientation", "sex_life",
                                         "gender_identity"}},
}

_CCPA_BROWSING_TABLES = {"browsing_history", "search_history", "recent_searches"}

_CCPA_EVIDENCE = {
    "identifiers": {"cols": {"name", "email", "phone", "address", "ssn"},
                    "types": {"email", "ssn"}, "type_prefixes": ("phone",)},
    "commercial_information": {"tables": {"purchase_history", "transactions",
                                          "orders", "cart"},
                               "cols": {"purchase", "transaction", "order_total",
                                        "payment"}},
    "browsing_search_history": {"tables": _CCPA_BROWSING_TABLES,
                                "cols": {"browsing", "search_query", "search_term"}},
    "geolocation_data": {"tables": {"geolocation", "location_history", "gps_log"},
                         "cols": {"geolocation", "location", "gps"}},
    "biometric_information": {"cols": {"biometric_info", "voice_recording",
                                       "face_geometry", "fingerprint", "biometric"}},
    "professional_employment": {"cols": {"employment", "employer", "occupation",
                                         "salary", "income"}},
    "education_information": {"cols": {"education", "school", "university",
                                      "degree", "gpa"}},
}


def _extract_evidence(actions):
    """Split the run's actions into evidence sets used for coverage scoring."""
    pii_types, sens_cols, pii_tbls, action_names = set(), set(), set(), set()
    for a in actions:
        if not isinstance(a, dict):
            continue
        action_names.add(a.get("action", ""))
        for pii in a.get("pii_types_found", []):
            if not isinstance(pii, str):
                continue
            if pii.startswith("sensitive_column:"):
                sens_cols.add(pii.split(":", 1)[1].lower())
            elif pii.startswith("pii_table:"):
                pii_tbls.add(pii.split(":", 1)[1].lower())
            else:
                pii_types.add(pii)
    return pii_types, sens_cols, pii_tbls, action_names


def _is_covered(evidence, pii_types, sens_cols, pii_tbls, action_names):
    if sens_cols & evidence.get("cols", frozenset()):
        return True
    if pii_tbls & evidence.get("tables", frozenset()):
        return True
    if pii_types & evidence.get("types", frozenset()):
        return True
    for prefix in evidence.get("type_prefixes", ()):
        if any(t.startswith(prefix) for t in pii_types):
            return True
    if action_names & evidence.get("actions", frozenset()):
        return True
    return False


def _evaluate(evidence_map, pii_types, sens_cols, pii_tbls, action_names):
    covered, gaps = [], []
    for identifier, evidence in evidence_map.items():
        if _is_covered(evidence, pii_types, sens_cols, pii_tbls, action_names):
            covered.append(identifier)
        else:
            gaps.append(identifier)
    return covered, gaps


def generate_compliance_report(mode: str, actions: list[dict], verification_passed: bool) -> dict:
    """Build a per-run compliance report.

    ``identifiers_covered`` / ``gaps`` are computed for *every* framework the
    mode selects — HIPAA reports all 18 Safe Harbor identifiers (finding #6),
    and GDPR/CCPA are no longer empty-but-named (findings #7/#28). ``limitations``
    records the honest boundaries of what was actually delivered so the framework
    label can never imply more than the run performed.
    """
    profile = get_compliance_profile(mode)
    pii_types, sens_cols, pii_tbls, action_names = _extract_evidence(actions)

    report = {
        "compliance_framework": profile.name,
        "mode": mode,
        "verification_passed": verification_passed,
        "identifiers_covered": [],
        "gaps": [],
        "limitations": [],
    }

    covered: list[str] = []
    gaps: list[str] = []
    limitations: list[str] = []

    if mode in ("hipaa", "all"):
        c, g = _evaluate(_HIPAA_EVIDENCE, pii_types, sens_cols, pii_tbls, action_names)
        covered += c
        gaps += g
        limitations.append(
            "HIPAA Safe Harbor dates/geography: columns named date_of_birth/dob "
            "and zip/city/address are fully redacted when present, but free-text "
            "dates and ZIP codes are neither generalized to year nor truncated to "
            "3 digits by the running pipeline (see compliance.generalize_date / "
            "truncate_zip / ComplianceProfile.transform_value) — treat 'dates' and "
            "'geographic_subdivisions' coverage as column-level only."
        )

    if mode in ("gdpr", "all"):
        c, g = _evaluate(_GDPR_EVIDENCE, pii_types, sens_cols, pii_tbls, action_names)
        covered += c
        gaps += g
        limitations.append(
            "GDPR Article 9 special-category detection is column-name-based only; "
            "special-category data in free-text columns (notes/bio/message) is NOT "
            "detected or removed."
        )
        # 'free-text special categories' can never be certified removed here.
        gaps.append("free_text_special_categories")
        if profile.delete_all_user_content:
            # Flag is read (no longer dead): HYGEIA does not blanket-delete all
            # user content, so this is surfaced as an explicit, un-closeable gap.
            gaps.append("full_user_content_deletion")
            limitations.append(
                "delete_all_user_content is advisory: HYGEIA redacts known "
                "sensitive columns and nukes known PII tables but does NOT "
                "blanket-delete all user content."
            )

    if mode in ("ccpa", "all"):
        c, g = _evaluate(_CCPA_EVIDENCE, pii_types, sens_cols, pii_tbls, action_names)
        covered += c
        gaps += g
        limitations.append(
            "CCPA categories are detected by table/column name; behavioral or "
            "free-text personal information outside known tables/columns may not "
            "be captured."
        )
        if profile.delete_browsing_history and not (pii_tbls & _CCPA_BROWSING_TABLES):
            # Flag is read (no longer dead): the delete IS delivered via table
            # nukes, so when nothing was removed we say so rather than implying it.
            limitations.append(
                "delete_browsing_history requested but no browsing/search-history "
                "tables were found to delete in this dump (nothing removed)."
            )

    covered_set = set(covered)
    seen = set()
    deduped_gaps = []
    for item in gaps:
        if item in covered_set or item in seen:
            continue
        seen.add(item)
        deduped_gaps.append(item)

    report["identifiers_covered"] = covered
    report["gaps"] = deduped_gaps
    report["limitations"] = limitations
    return report
