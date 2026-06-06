"""
HYGEIA -- Forensic-grade PII sanitization engine.

Classifies, sanitizes, verifies, and audits filesystem dumps.
WAL-aware SQLite pipeline, binary plist redaction, EXIF stripping,
post-sanitization verification, and compliance-ready audit manifests.

Ships with iOS rules. Engine works on any SQLite database, binary
plist, or image regardless of platform. Swap the JSON rule files
in hygeia/rules/ for other platforms.
"""

__version__ = "1.0.0"
