"""
Tests for new PII patterns added in feat/pii-patterns.

Covers all 24 new detection types (16 in PII_PATTERNS + 8 in CONTEXT_PATTERNS)
with at least 2 tests per pattern: one true positive and one true negative or
false-positive rejection.
"""

import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hygeia.verifier import (
    PII_PATTERNS,
    _is_false_positive,
    _scan_context_patterns,
    scan_text_files,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def matches_pattern(pattern_name: str, text: str) -> list[str]:
    """Return list of matched strings for a PII_PATTERNS entry."""
    pat = PII_PATTERNS[pattern_name]
    return [m.group() for m in pat.finditer(text)]


def context_matches_pattern(pattern_name: str, text: str) -> list[str]:
    """Return list of matched strings for a CONTEXT_PATTERNS entry."""
    results = _scan_context_patterns(text, "test.txt")
    return [m.match_text for m in results if m.pattern_name == pattern_name]


# ─────────────────────────────────────────────────────────────────────────────
# UK National Insurance Number
# ─────────────────────────────────────────────────────────────────────────────

def test_uk_nin_matches_valid():
    assert matches_pattern("uk_nin", "NI: AB123456C") != []


def test_uk_nin_matches_various_formats():
    # Q is excluded from UK NIN prefix — use a valid two-letter prefix
    assert matches_pattern("uk_nin", "NI number is JG123456A") != []


def test_uk_nin_rejects_invalid_suffix():
    # E is not a valid suffix (must be A-D)
    assert matches_pattern("uk_nin", "AB123456E") == []


def test_uk_nin_not_false_positive_for_random_alphanumeric():
    # 2 letters + 6 digits but missing the required suffix letter — not a NIN
    assert matches_pattern("uk_nin", "ZZ12345") == []


# ─────────────────────────────────────────────────────────────────────────────
# Indian PAN
# ─────────────────────────────────────────────────────────────────────────────

def test_indian_pan_matches_valid():
    assert matches_pattern("indian_pan", "PAN: ABCDE1234F") != []


def test_indian_pan_matches_in_sentence():
    assert matches_pattern("indian_pan", "Taxpayer PAN is AABCP1234C.") != []


def test_indian_pan_rejects_lowercase():
    # PAN must be uppercase
    assert matches_pattern("indian_pan", "abcde1234f") == []


def test_indian_pan_rejects_wrong_format():
    # Missing final letter
    assert matches_pattern("indian_pan", "ABCDE1234") == []


# ─────────────────────────────────────────────────────────────────────────────
# Indian Aadhaar
# ─────────────────────────────────────────────────────────────────────────────

def test_indian_aadhaar_matches_hyphen():
    assert matches_pattern("indian_aadhaar", "Aadhaar: 1234-5678-9012") != []


def test_indian_aadhaar_matches_space():
    assert matches_pattern("indian_aadhaar", "UID 9876 5432 1098") != []


def test_indian_aadhaar_rejects_no_separator():
    # Without separator it's just a 12-digit number — not matched by this pattern
    assert matches_pattern("indian_aadhaar", "123456789012") == []


def test_indian_aadhaar_rejects_short():
    assert matches_pattern("indian_aadhaar", "1234-5678-90") == []


# ─────────────────────────────────────────────────────────────────────────────
# DEA Number
# ─────────────────────────────────────────────────────────────────────────────

def test_dea_number_matches_valid():
    assert matches_pattern("dea_number", "DEA: AB1234563") != []


def test_dea_number_matches_in_context():
    assert matches_pattern("dea_number", "prescriber DEA BX7654321") != []


def test_dea_number_rejects_too_short():
    assert matches_pattern("dea_number", "AB12345") == []


def test_dea_number_rejects_non_letter_prefix():
    # Starts with digit — not a DEA number
    assert matches_pattern("dea_number", "12B345678") == []


# ─────────────────────────────────────────────────────────────────────────────
# Medicare MBI
# ─────────────────────────────────────────────────────────────────────────────

def test_medicare_mbi_matches_valid():
    # Format: digit UC UC/digit digit UC UC/digit digit UC UC digit digit
    assert matches_pattern("medicare_mbi", "MBI: 1EG4-TE5-MK72".replace("-", "")) != []


def test_medicare_mbi_matches_another():
    assert matches_pattern("medicare_mbi", "2BB3CC4DD55") != []


def test_medicare_mbi_rejects_wrong_length():
    assert matches_pattern("medicare_mbi", "1AB2CD3EF") == []


# ─────────────────────────────────────────────────────────────────────────────
# VIN
# ─────────────────────────────────────────────────────────────────────────────

def test_vin_matches_valid():
    assert matches_pattern("vin", "VIN: 1HGBH41JXMN109186") != []


def test_vin_matches_17_chars():
    assert matches_pattern("vin", "Vehicle: 3VWFE21C04M000001") != []


def test_vin_rejects_16_chars():
    assert matches_pattern("vin", "1HGBH41JXMN10918") == []


def test_vin_rejects_invalid_chars():
    # I, O, Q are excluded from VINs
    assert matches_pattern("vin", "1HGBH41JXMN1091O") == []


# ─────────────────────────────────────────────────────────────────────────────
# US EIN
# ─────────────────────────────────────────────────────────────────────────────

def test_us_ein_matches_valid():
    assert matches_pattern("us_ein", "EIN: 12-3456789") != []


def test_us_ein_matches_in_sentence():
    assert matches_pattern("us_ein", "Tax ID (EIN) is 98-7654321.") != []


def test_us_ein_rejects_no_hyphen():
    # EIN without hyphen won't match (requires XX-XXXXXXX format)
    assert matches_pattern("us_ein", "123456789") == []


def test_us_ein_rejects_wrong_split():
    # SSN-style split (3-2-4) not EIN (2-7)
    assert matches_pattern("us_ein", "123-45-6789") == []


# ─────────────────────────────────────────────────────────────────────────────
# SWIFT / BIC
# ─────────────────────────────────────────────────────────────────────────────

def test_swift_bic_matches_8char():
    # DEUTDEDB is Deutsche Bank Frankfurt — 6 alpha + 2 alpha
    assert matches_pattern("swift_bic", "SWIFT: DEUTDEDB") != []


def test_swift_bic_matches_11char():
    assert matches_pattern("swift_bic", "BIC: BOFAUS3NXXX") != []


def test_swift_bic_all_alpha_8_is_false_positive():
    """All-alpha 8-char codes collide with identifier strings; filtered."""
    assert _is_false_positive("data/config.txt", "swift_bic", "ABCDEFGH") is True


def test_swift_bic_with_digit_not_false_positive():
    """BIC with digit in position 7-8 is not suppressed."""
    assert _is_false_positive("data/config.txt", "swift_bic", "DEUTDE2X") is False


# ─────────────────────────────────────────────────────────────────────────────
# Bitcoin address
# ─────────────────────────────────────────────────────────────────────────────

def test_bitcoin_address_matches_legacy():
    assert matches_pattern("bitcoin_address", "Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf") != []


def test_bitcoin_address_matches_bech32():
    assert matches_pattern("bitcoin_address", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") != []


def test_bitcoin_address_rejects_too_short():
    assert _is_false_positive("data.txt", "bitcoin_address", "1A1zP1eP5QGe") is True


def test_bitcoin_address_rejects_invalid_prefix():
    # Starts with 2 — not a valid legacy address prefix
    assert matches_pattern("bitcoin_address", "2A1zP1eP5QGefi2DMPTfTL5SLmv7Divf") == []


# ─────────────────────────────────────────────────────────────────────────────
# Ethereum address
# ─────────────────────────────────────────────────────────────────────────────

def test_ethereum_address_matches_valid():
    assert matches_pattern("ethereum_address", "wallet: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") != []


def test_ethereum_address_matches_lowercase():
    assert matches_pattern("ethereum_address", "0xabcdef1234567890abcdef1234567890abcdef12") != []


def test_ethereum_address_rejects_too_short():
    assert matches_pattern("ethereum_address", "0xabc123") == []


def test_ethereum_address_zero_padded_is_false_positive():
    """0x + 24 leading zeros = padded small integer, not a real wallet."""
    assert _is_false_positive(
        "data.bin", "ethereum_address",
        "0x000000000000000000000000de0B295669a9FD93"
    ) is True


# ─────────────────────────────────────────────────────────────────────────────
# JWT token
# ─────────────────────────────────────────────────────────────────────────────

def test_jwt_token_matches_valid():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert matches_pattern("jwt_token", jwt) != []


def test_jwt_token_matches_in_log():
    jwt = (
        "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9"
        ".eyJ1c2VyIjoiYWxpY2UifQ"
        ".MEUCIQDd0kbHZP5N8KlqpRhb3j2Y9Z"
    )
    assert matches_pattern("jwt_token", jwt) != []


def test_jwt_token_rejects_two_segments_only():
    # JWT must have exactly 3 dot-separated segments
    bad = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    assert matches_pattern("jwt_token", bad) == []


# ─────────────────────────────────────────────────────────────────────────────
# AWS access key
# ─────────────────────────────────────────────────────────────────────────────

def test_aws_access_key_matches_valid():
    assert matches_pattern("aws_access_key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE") != []


def test_aws_access_key_matches_in_config():
    assert matches_pattern("aws_access_key", "access_key: AKIAI44QH8DHBEXAMPLE") != []


def test_aws_access_key_rejects_wrong_prefix():
    # Must start with AKIA
    assert matches_pattern("aws_access_key", "ASIA44QH8DHBEXAMPLE123") == []


def test_aws_access_key_rejects_short():
    assert matches_pattern("aws_access_key", "AKIAIO") == []


# ─────────────────────────────────────────────────────────────────────────────
# GitHub token
# ─────────────────────────────────────────────────────────────────────────────

def test_github_token_matches_ghp():
    assert matches_pattern("github_token", "token: ghp_" + "A" * 36) != []


def test_github_token_matches_gho():
    assert matches_pattern("github_token", "oauth: gho_" + "B" * 36) != []


def test_github_token_rejects_wrong_prefix():
    assert matches_pattern("github_token", "xyz_" + "A" * 36) == []


def test_github_token_rejects_too_short():
    assert matches_pattern("github_token", "ghp_ABCDE") == []


# ─────────────────────────────────────────────────────────────────────────────
# Generic API key
# ─────────────────────────────────────────────────────────────────────────────

def test_generic_api_key_matches_sk_live():
    assert matches_pattern("generic_api_key", "sk-live-ABCDEFGHIJKLMNOPQRSTU") != []


def test_generic_api_key_matches_pk_test():
    assert matches_pattern("generic_api_key", "pk_test_ABCDEFGHIJKLMNOPQRSTU") != []


def test_generic_api_key_rejects_wrong_prefix():
    assert matches_pattern("generic_api_key", "rk-live-ABCDEFGHIJKLMNOPQRSTU") == []


def test_generic_api_key_rejects_wrong_env():
    assert matches_pattern("generic_api_key", "sk-staging-ABCDEFGHIJKLMNOPQRSTU") == []


# ─────────────────────────────────────────────────────────────────────────────
# Slack token
# ─────────────────────────────────────────────────────────────────────────────

def test_slack_token_matches_bot():
    assert matches_pattern("slack_token", "SLACK_TOKEN=xoxb-123456789012-ABCDEFGHIJKLMNOP") != []


def test_slack_token_matches_user():
    assert matches_pattern("slack_token", "token=xoxp-987654321098-zyxwvutsrqpo") != []


def test_slack_token_rejects_wrong_prefix():
    assert matches_pattern("slack_token", "xoxz-123456789012-ABCDEF") == []


def test_slack_token_rejects_too_short():
    assert matches_pattern("slack_token", "xoxb-123") == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — US Passport
# ─────────────────────────────────────────────────────────────────────────────

def test_us_passport_matches_with_context():
    text = "passport number: 123456789 issued 2022"
    assert context_matches_pattern("us_passport", text) != []


def test_us_passport_matches_letter_prefix():
    # US passport: optional letter + exactly 9 digits = 10 chars total
    text = "US passport: A123456789 expires 2030"
    assert context_matches_pattern("us_passport", text) != []


def test_us_passport_no_context_not_matched():
    text = "reference code: 123456789"
    assert context_matches_pattern("us_passport", text) == []


def test_us_passport_context_window_respected():
    # Keyword is >120 chars away from the number — should not match
    far_text = "passport " + " " * 200 + "123456789"
    assert context_matches_pattern("us_passport", far_text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — Driver's License
# ─────────────────────────────────────────────────────────────────────────────

def test_drivers_license_matches_with_dl():
    text = "DL number: B1234567"
    assert context_matches_pattern("drivers_license", text) != []


def test_drivers_license_matches_with_license_keyword():
    text = "driver license: 123456789"
    assert context_matches_pattern("drivers_license", text) != []


def test_drivers_license_no_context_not_matched():
    text = "reference: 12345678"
    assert context_matches_pattern("drivers_license", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — Canadian SIN
# ─────────────────────────────────────────────────────────────────────────────

def test_canadian_sin_matches_with_context():
    text = "SIN: 123 456 789"
    assert context_matches_pattern("canadian_sin", text) != []


def test_canadian_sin_matches_hyphen_format():
    text = "social insurance number: 987-654-321"
    assert context_matches_pattern("canadian_sin", text) != []


def test_canadian_sin_no_context_not_matched():
    text = "ref: 123 456 789"
    assert context_matches_pattern("canadian_sin", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — Australian TFN
# ─────────────────────────────────────────────────────────────────────────────

def test_australian_tfn_matches_with_context():
    text = "TFN: 123 456 782"
    assert context_matches_pattern("australian_tfn", text) != []


def test_australian_tfn_matches_tax_file():
    text = "tax file number: 987 654 321"
    assert context_matches_pattern("australian_tfn", text) != []


def test_australian_tfn_no_context_not_matched():
    text = "pin: 123 456 789"
    assert context_matches_pattern("australian_tfn", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — US Routing Number
# ─────────────────────────────────────────────────────────────────────────────

def test_us_routing_matches_with_routing():
    text = "routing number: 021000021"
    assert context_matches_pattern("us_routing_number", text) != []


def test_us_routing_matches_with_aba():
    text = "ABA: 121000358"
    assert context_matches_pattern("us_routing_number", text) != []


def test_us_routing_no_context_not_matched():
    text = "code: 021000021"
    assert context_matches_pattern("us_routing_number", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — NPI
# ─────────────────────────────────────────────────────────────────────────────

def test_npi_matches_with_npi_keyword():
    text = "NPI: 1234567893"
    assert context_matches_pattern("npi", text) != []


def test_npi_matches_with_provider_keyword():
    text = "provider ID: 1023456789"
    assert context_matches_pattern("npi", text) != []


def test_npi_no_context_not_matched():
    text = "record id: 1234567890"
    assert context_matches_pattern("npi", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — Date of Birth
# ─────────────────────────────────────────────────────────────────────────────

def test_dob_matches_dob_label():
    text = "DOB: 03/15/1985"
    assert context_matches_pattern("date_of_birth", text) != []


def test_dob_matches_date_of_birth_label():
    text = "Date of Birth: 1990-07-22"
    assert context_matches_pattern("date_of_birth", text) != []


def test_dob_matches_birthdate_label():
    text = "birthdate=01/01/2000"
    assert context_matches_pattern("date_of_birth", text) != []


def test_dob_no_label_not_matched():
    # A bare date without DOB/birthdate label should not fire
    text = "expiry: 03/15/2030"
    assert context_matches_pattern("date_of_birth", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — Password in key-value
# ─────────────────────────────────────────────────────────────────────────────

def test_password_kv_matches_colon_format():
    text = "password: s3cr3tP@ssw0rd"
    assert context_matches_pattern("password_kv", text) != []


def test_password_kv_matches_equals_format():
    text = "pwd=myP@ssword123"
    assert context_matches_pattern("password_kv", text) != []


def test_password_kv_matches_passwd():
    text = "passwd: hunter2"
    assert context_matches_pattern("password_kv", text) != []


def test_password_kv_no_match_without_assignment():
    # "password" appears in a sentence without assignment operator — no match
    text = "the user forgot their password last week"
    assert context_matches_pattern("password_kv", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT_PATTERNS — AWS secret key
# ─────────────────────────────────────────────────────────────────────────────

def test_aws_secret_key_matches_with_aws_keyword():
    text = "aws secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert context_matches_pattern("aws_secret_key", text) != []


def test_aws_secret_key_matches_with_secret_keyword():
    text = "secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert context_matches_pattern("aws_secret_key", text) != []


def test_aws_secret_key_no_context_not_matched():
    # 40-char base64 without aws/secret context — not matched
    text = "hash: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert context_matches_pattern("aws_secret_key", text) == []


# ─────────────────────────────────────────────────────────────────────────────
# Integration: scan_text_files picks up new patterns in real files
# ─────────────────────────────────────────────────────────────────────────────

def test_scan_text_detects_jwt():
    d = tempfile.mkdtemp()
    root = Path(d)
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    (root / "tokens.json").write_text(f'{{"access_token": "{jwt}"}}')
    matches = scan_text_files(root)
    assert any(m.pattern_name == "jwt_token" for m in matches), (
        f"jwt_token not found; got: {[m.pattern_name for m in matches]}"
    )
    shutil.rmtree(d)


def test_scan_text_detects_aws_access_key():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "creds.txt").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "aws_access_key" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_ethereum_address():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "wallet.txt").write_text("wallet=0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "ethereum_address" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_github_token():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "config.txt").write_text("GITHUB_TOKEN=ghp_" + "X" * 36 + "\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "github_token" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_password_kv_in_log():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "app.log").write_text("2024-01-01 login: password=MyS3cret!\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "password_kv" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_dob_in_csv():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "records.csv").write_text("name,dob\nAlice,DOB: 04/20/1990\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "date_of_birth" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_vin():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "vehicle.txt").write_text("VIN: 1HGBH41JXMN109186\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "vin" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_us_ein():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "tax.txt").write_text("EIN: 12-3456789\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "us_ein" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_slack_token():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "env.txt").write_text("SLACK_BOT_TOKEN=xoxb-123456789012-ABCDEFGHIJKLMNOP\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "slack_token" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_bitcoin():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "crypto.txt").write_text("BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "bitcoin_address" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_indian_pan():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "user.txt").write_text("PAN: ABCDE1234F\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "indian_pan" for m in matches)
    shutil.rmtree(d)


def test_scan_text_detects_uk_nin():
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "employee.txt").write_text("NI: AB123456C\n")
    matches = scan_text_files(root)
    assert any(m.pattern_name == "uk_nin" for m in matches)
    shutil.rmtree(d)


def test_scan_text_clean_no_new_pattern_false_positives():
    """A clean file with no PII should produce zero matches from new patterns."""
    d = tempfile.mkdtemp()
    root = Path(d)
    (root / "readme.txt").write_text(
        "This is a normal config file with version 1.2.3 and build number 20240101.\n"
        "No personal data stored here.\n"
    )
    matches = scan_text_files(root)
    new_pattern_names = set(PII_PATTERNS.keys()) - {
        "email", "phone_us", "phone_intl", "ssn", "credit_card",
        "ip_v4", "ip_v6", "apple_id", "gps_coord", "imei",
        "device_name", "iban", "mac_addr",
    }
    new_matches = [m for m in matches if m.pattern_name in new_pattern_names]
    assert len(new_matches) == 0, (
        "False positives from new patterns: "
        + ", ".join(f"{m.pattern_name}={m.match_text!r}" for m in new_matches)
    )
    shutil.rmtree(d)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} -- {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
