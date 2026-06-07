"""
HYGEIA Exceptions — typed error hierarchy for the sanitization pipeline.
"""


class HygeiaError(Exception):
    """Base exception for all HYGEIA errors."""
    pass


class DatabaseLockError(HygeiaError):
    """Database locked after all retry attempts."""
    pass


class DatabaseCorruptionError(HygeiaError):
    """Database failed integrity check pre- or post-sanitization."""
    pass


class VerificationFailedError(HygeiaError):
    """Post-sanitization verification found residual PII."""
    pass
