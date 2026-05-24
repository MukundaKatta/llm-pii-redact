"""llm-pii-redact - regex-based PII redaction for LLM prompts.

Scan text for emails, phone numbers, SSNs, credit cards, IPs, IBANs,
and URLs. Each match is replaced with a placeholder like ``<EMAIL_0>``
and the original value is kept in a mapping you can use to restore
the original text after the LLM responds.

    from llm_pii_redact import PIIRedactor

    r = PIIRedactor()
    redacted, mapping = r.redact("Email me at ops@example.com")
    # redacted == "Email me at <EMAIL_0>"
    answer = call_llm(redacted)
    final = r.restore(answer, mapping)

Pick a subset of detectors by name:

    r = PIIRedactor(types={"EMAIL", "PHONE_US"})

Register your own pattern (e.g. a vendor API key shape):

    r.add_pattern("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}")

Zero runtime dependencies. Stdlib ``re`` only.
"""

from llm_pii_redact.redact import (
    Detection,
    PIIRedactor,
    PIIType,
)

__version__ = "0.1.0"

__all__ = [
    "Detection",
    "PIIRedactor",
    "PIIType",
    "__version__",
]
