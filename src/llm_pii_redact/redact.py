"""Regex-based PII redactor for LLM input sanitization.

The redactor scans text for common PII patterns and replaces each match
with a placeholder like ``<EMAIL_0>``. Placeholders are stable per type
and per input, so the same input always produces the same redacted
output. A mapping from placeholder back to the original value is returned
so callers can restore the original text once the LLM has responded.

The module is plain stdlib. The only dependency is ``re``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from re import Pattern


class PIIType(StrEnum):
    """Built-in PII categories the redactor knows about."""

    EMAIL = "EMAIL"
    PHONE_US = "PHONE_US"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IP_V4 = "IP_V4"
    IP_V6 = "IP_V6"
    IBAN = "IBAN"
    URL = "URL"


@dataclass(frozen=True)
class Detection:
    """One PII match found in the input text.

    Attributes:
        type: The detector that produced this match (e.g. ``"EMAIL"``).
        value: The exact substring captured.
        start: Inclusive start index into the original text.
        end: Exclusive end index into the original text.
    """

    type: str
    value: str
    start: int
    end: int


# --- Patterns ----------------------------------------------------------------
#
# The patterns below intentionally accept a useful subset of each format
# rather than the full grammar. The goal is to catch values that look like
# PII in real user prompts, not to validate inputs for a payments system.

# RFC 5322 subset: local-part allows letters, digits, and common punctuation
# such as ``.`` ``_`` ``%`` ``+`` ``-``. Domain is one or more labels of
# letters/digits/hyphens separated by dots, ending with a 2+ letter TLD.
_EMAIL = r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"

# US phone numbers: optional +1, optional parens around area code, optional
# dashes/spaces/dots between groups. Matches 10-digit or 11-digit (+1) forms.
_PHONE_US = (
    r"(?<!\d)"
    r"(?:\+?1[\s.\-]?)?"
    r"(?:\(\d{3}\)|\d{3})"
    r"[\s.\-]?\d{3}[\s.\-]?\d{4}"
    r"(?!\d)"
)

# US Social Security Number: XXX-XX-XXXX or 9 contiguous digits. The 9-digit
# form requires word boundaries so it does not eat the middle of a longer
# number such as a credit card.
_SSN = r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b"

# Credit cards: 13-19 digit runs, optionally split into groups by spaces
# or dashes. Brand prefixes are accepted broadly; the Luhn check below is
# the real filter for false positives.
_CREDIT_CARD = (
    r"(?<!\d)"
    r"(?:\d[ \-]?){12,18}\d"
    r"(?!\d)"
)

# IPv4: four octets 0-255 separated by dots.
_IP_V4 = (
    r"\b"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"\b"
)

# IPv6: simple form that requires at least one ``::`` or 8 groups of
# hex digits separated by ``:``. This is a deliberately loose pattern.
_IP_V6 = (
    r"(?<![\w:])"
    r"(?:"
    r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
    r"|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:"
    r"|"
    r":(?::[A-Fa-f0-9]{1,4}){1,7}"
    r"|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}(?::[A-Fa-f0-9]{1,4}){1,6}"
    r")"
    r"(?![\w:])"
)

# IBAN: two-letter country code, two check digits, then 11-30 alphanumerics.
_IBAN = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"

# URL: http or https only, followed by ``://`` and host/path characters.
_URL = r"\bhttps?://[^\s<>\"'\)]+"


_DEFAULT_PATTERNS: dict[str, str] = {
    PIIType.EMAIL.value: _EMAIL,
    PIIType.PHONE_US.value: _PHONE_US,
    PIIType.SSN.value: _SSN,
    PIIType.CREDIT_CARD.value: _CREDIT_CARD,
    PIIType.IP_V4.value: _IP_V4,
    PIIType.IP_V6.value: _IP_V6,
    PIIType.IBAN.value: _IBAN,
    PIIType.URL.value: _URL,
}


def _luhn_ok(number: str) -> bool:
    """Return True if the digit-only string passes the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    # Process digits from right to left. Double every second digit.
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Types that require an extra validator beyond the raw regex.
_VALIDATORS = {
    PIIType.CREDIT_CARD.value: lambda s: _luhn_ok(s),
}


class PIIRedactor:
    """Detect, redact, and restore PII in plain text.

    Args:
        types: An iterable of type names to enable. When ``None`` all
            built-in types are enabled. Unknown names raise ``ValueError``.

    Example:
        >>> r = PIIRedactor()
        >>> redacted, mapping = r.redact("ping ops@example.com")
        >>> "ops@example.com" not in redacted
        True
        >>> r.restore(redacted, mapping)
        'ping ops@example.com'
    """

    def __init__(self, types: set[str] | None = None) -> None:
        if types is None:
            enabled = set(_DEFAULT_PATTERNS.keys())
        else:
            enabled = {str(t) for t in types}
            unknown = enabled - set(_DEFAULT_PATTERNS.keys())
            if unknown:
                raise ValueError(f"unknown PII types: {sorted(unknown)}")

        # Preserve insertion order so detection is deterministic.
        self._patterns: dict[str, Pattern[str]] = {}
        for name in _DEFAULT_PATTERNS:
            if name in enabled:
                self._patterns[name] = re.compile(_DEFAULT_PATTERNS[name])

    def add_pattern(self, name: str, regex_pattern: str) -> None:
        """Register an additional named detector.

        Args:
            name: Uppercase type label used in placeholders, e.g. ``"AWS_KEY"``.
            regex_pattern: Standard Python regex source string.

        Raises:
            ValueError: If ``name`` is empty or the regex fails to compile.
        """
        if not name:
            raise ValueError("name must be non-empty")
        try:
            self._patterns[name] = re.compile(regex_pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex for {name!r}: {exc}") from exc

    def detect(self, text: str) -> list[Detection]:
        """Return every PII match in ``text`` without modifying it.

        Matches are returned in document order. When two enabled detectors
        overlap on the same span, the detector registered first wins; the
        loser is dropped to keep the result unambiguous.
        """
        if not text:
            return []

        raw: list[Detection] = []
        for name, pat in self._patterns.items():
            validator = _VALIDATORS.get(name)
            for m in pat.finditer(text):
                value = m.group(0)
                if validator is not None and not validator(value):
                    continue
                raw.append(Detection(type=name, value=value, start=m.start(), end=m.end()))

        # Sort by start, then by registration order (preserved by the input list).
        raw.sort(key=lambda d: (d.start, d.end))

        # Drop matches that overlap with one already accepted. Earlier matches
        # win because they were sorted first.
        accepted: list[Detection] = []
        last_end = -1
        for d in raw:
            if d.start >= last_end:
                accepted.append(d)
                last_end = d.end
        return accepted

    def redact(self, text: str) -> tuple[str, dict[str, str]]:
        """Replace each detected PII span with a stable placeholder.

        Returns a tuple of ``(redacted_text, mapping)`` where ``mapping``
        sends each placeholder string back to its original value. Repeated
        values share a single placeholder so the output is deterministic.
        """
        detections = self.detect(text)
        if not detections:
            return text, {}

        # Assign placeholders per type. The first time a value of a given
        # type is seen, it gets the next available index for that type.
        per_type_index: dict[str, int] = {}
        # value -> placeholder, keyed by (type, value) so two types can
        # share a string without colliding (rare but well-defined).
        value_to_placeholder: dict[tuple[str, str], str] = {}
        mapping: dict[str, str] = {}

        for d in detections:
            key = (d.type, d.value)
            if key not in value_to_placeholder:
                idx = per_type_index.get(d.type, 0)
                placeholder = f"<{d.type}_{idx}>"
                per_type_index[d.type] = idx + 1
                value_to_placeholder[key] = placeholder
                mapping[placeholder] = d.value

        # Build the redacted text by walking detections in order.
        out: list[str] = []
        cursor = 0
        for d in detections:
            out.append(text[cursor : d.start])
            out.append(value_to_placeholder[(d.type, d.value)])
            cursor = d.end
        out.append(text[cursor:])
        return "".join(out), mapping

    @staticmethod
    def restore(text: str, mapping: dict[str, str]) -> str:
        """Swap placeholders in ``text`` back to their original values.

        Unknown placeholders in ``text`` are left alone. The mapping is
        applied longest-key-first so that, for example, ``<EMAIL_10>``
        does not collide with ``<EMAIL_1>``.
        """
        if not mapping:
            return text
        # Sort by key length descending to avoid prefix collisions.
        for placeholder in sorted(mapping.keys(), key=len, reverse=True):
            text = text.replace(placeholder, mapping[placeholder])
        return text
