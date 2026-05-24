"""Tests for the PII redactor."""

from __future__ import annotations

import pytest

from llm_pii_redact import Detection, PIIRedactor, PIIType

# --- Email -------------------------------------------------------------------


def test_email_basic_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("write to john@example.com")
    assert len(detections) == 1
    assert detections[0].type == PIIType.EMAIL.value
    assert detections[0].value == "john@example.com"


def test_email_plus_tag_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("alias is a.b+filter@sub.example.co")
    assert any(d.value == "a.b+filter@sub.example.co" for d in detections)


def test_email_miss_on_bare_at() -> None:
    r = PIIRedactor()
    assert r.detect("@notanemail") == []


# --- US phone ----------------------------------------------------------------


def test_phone_with_dashes_hit() -> None:
    r = PIIRedactor()
    redacted, mapping = r.redact("call 555-123-4567 today")
    assert redacted == "call <PHONE_US_0> today"
    assert mapping == {"<PHONE_US_0>": "555-123-4567"}


def test_phone_parens_and_plus_one_hit() -> None:
    r = PIIRedactor()
    for src in ("+1 (555) 123-4567", "+15551234567", "(555) 123 4567"):
        detections = r.detect(src)
        assert len(detections) == 1, f"missed phone form: {src!r}"
        assert detections[0].type == PIIType.PHONE_US.value


def test_phone_miss_on_short_number() -> None:
    r = PIIRedactor()
    assert r.detect("press 911 now") == []


# --- SSN ---------------------------------------------------------------------


def test_ssn_dashed_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("SSN 123-45-6789")
    assert [(d.type, d.value) for d in detections] == [(PIIType.SSN.value, "123-45-6789")]


def test_ssn_nine_digit_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("SSN 123456789 maybe")
    assert any(d.type == PIIType.SSN.value and d.value == "123456789" for d in detections)


def test_ssn_miss_on_longer_run() -> None:
    r = PIIRedactor(types={PIIType.SSN.value})
    # 10 contiguous digits should not match SSN alone.
    assert r.detect("ref 1234567890 here") == []


# --- Credit card -------------------------------------------------------------


def test_credit_card_luhn_valid_visa_hit() -> None:
    r = PIIRedactor()
    # Well-known Visa test number that passes Luhn.
    detections = r.detect("card 4111 1111 1111 1111 expiring")
    assert any(d.type == PIIType.CREDIT_CARD.value for d in detections)


def test_credit_card_luhn_invalid_rejected() -> None:
    r = PIIRedactor()
    # Same shape, last digit flipped to break Luhn.
    detections = r.detect("card 4111 1111 1111 1112 expiring")
    assert not any(d.type == PIIType.CREDIT_CARD.value for d in detections)


def test_credit_card_amex_15_digits_hit() -> None:
    r = PIIRedactor()
    # Known Amex test number, valid Luhn.
    detections = r.detect("amex 3782 822463 10005 charge")
    assert any(d.type == PIIType.CREDIT_CARD.value for d in detections)


# --- IPv4 / IPv6 -------------------------------------------------------------


def test_ipv4_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("server 192.168.1.10 is up")
    assert any(d.type == PIIType.IP_V4.value and d.value == "192.168.1.10" for d in detections)


def test_ipv4_miss_on_out_of_range() -> None:
    r = PIIRedactor(types={PIIType.IP_V4.value})
    assert r.detect("server 999.999.999.999 fake") == []


def test_ipv6_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok")
    assert any(d.type == PIIType.IP_V6.value for d in detections)


def test_ipv6_compressed_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("loopback ::1 reachable")
    assert any(d.type == PIIType.IP_V6.value for d in detections)


# --- IBAN --------------------------------------------------------------------


def test_iban_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("send to DE89370400440532013000 please")
    assert any(d.type == PIIType.IBAN.value for d in detections)


def test_iban_miss_on_short_value() -> None:
    r = PIIRedactor(types={PIIType.IBAN.value})
    assert r.detect("DE89 short") == []


# --- URL ---------------------------------------------------------------------


def test_url_https_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("see https://example.com/path?q=1 for details")
    assert any(
        d.type == PIIType.URL.value and d.value.startswith("https://example.com")
        for d in detections
    )


def test_url_http_hit() -> None:
    r = PIIRedactor()
    detections = r.detect("plain http://x.test/y here")
    assert any(d.type == PIIType.URL.value for d in detections)


# --- Dedupe / placeholder behavior ------------------------------------------


def test_same_value_twice_shares_placeholder() -> None:
    r = PIIRedactor()
    redacted, mapping = r.redact("mail a@b.com and a@b.com again")
    # Only one mapping entry, used twice in the output.
    assert mapping == {"<EMAIL_0>": "a@b.com"}
    assert redacted.count("<EMAIL_0>") == 2


def test_distinct_values_get_distinct_placeholders() -> None:
    r = PIIRedactor()
    _, mapping = r.redact("a@b.com and c@d.com")
    assert set(mapping.values()) == {"a@b.com", "c@d.com"}
    assert set(mapping.keys()) == {"<EMAIL_0>", "<EMAIL_1>"}


def test_placeholders_namespaced_by_type() -> None:
    r = PIIRedactor()
    _, mapping = r.redact("a@b.com call 555-123-4567")
    assert "<EMAIL_0>" in mapping
    assert "<PHONE_US_0>" in mapping


# --- Redact + restore round trip --------------------------------------------


def test_redact_restore_round_trip() -> None:
    r = PIIRedactor()
    src = "Email me at john@example.com or call 555-123-4567"
    redacted, mapping = r.redact(src)
    assert "john@example.com" not in redacted
    assert "555-123-4567" not in redacted
    assert r.restore(redacted, mapping) == src


def test_restore_handles_unknown_placeholders() -> None:
    r = PIIRedactor()
    # Mapping has no <FOO_0>, so it must be left alone.
    out = r.restore("hello <FOO_0>", {"<EMAIL_0>": "a@b.com"})
    assert out == "hello <FOO_0>"


def test_restore_does_not_confuse_index_prefixes() -> None:
    r = PIIRedactor()
    text = "<EMAIL_10> and <EMAIL_1>"
    mapping = {"<EMAIL_1>": "one@x.com", "<EMAIL_10>": "ten@x.com"}
    assert r.restore(text, mapping) == "ten@x.com and one@x.com"


# --- Custom pattern ----------------------------------------------------------


def test_custom_pattern_detected_and_redacted() -> None:
    r = PIIRedactor()
    r.add_pattern("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}")
    redacted, mapping = r.redact("key=AKIAABCDEFGHIJKLMNOP ok")
    assert "<AWS_ACCESS_KEY_0>" in redacted
    assert mapping["<AWS_ACCESS_KEY_0>"] == "AKIAABCDEFGHIJKLMNOP"


def test_custom_pattern_invalid_regex_rejected() -> None:
    r = PIIRedactor()
    with pytest.raises(ValueError):
        r.add_pattern("BAD", "(")


def test_custom_pattern_name_required() -> None:
    r = PIIRedactor()
    with pytest.raises(ValueError):
        r.add_pattern("", r".+")


# --- Type filtering ----------------------------------------------------------


def test_partial_detection_email_only() -> None:
    r = PIIRedactor(types={PIIType.EMAIL.value})
    redacted, mapping = r.redact("a@b.com phone 555-123-4567")
    assert "555-123-4567" in redacted  # phone untouched
    assert "<EMAIL_0>" in redacted
    assert set(mapping.values()) == {"a@b.com"}


def test_unknown_type_name_raises() -> None:
    with pytest.raises(ValueError):
        PIIRedactor(types={"NOT_A_TYPE"})


# --- Edge cases --------------------------------------------------------------


def test_empty_text_returns_empty() -> None:
    r = PIIRedactor()
    redacted, mapping = r.redact("")
    assert redacted == ""
    assert mapping == {}
    assert r.detect("") == []


def test_no_pii_returns_text_unchanged() -> None:
    r = PIIRedactor()
    src = "no personal data here, just words"
    redacted, mapping = r.redact(src)
    assert redacted == src
    assert mapping == {}


def test_detect_returns_dataclass_with_span() -> None:
    r = PIIRedactor()
    src = "see john@example.com here"
    detections = r.detect(src)
    assert len(detections) == 1
    d = detections[0]
    assert isinstance(d, Detection)
    assert src[d.start : d.end] == d.value


def test_overlapping_matches_handled_deterministically() -> None:
    # A URL that contains an email-like substring. The URL pattern is
    # registered after EMAIL, so EMAIL wins the overlap on equal start.
    # Either way, the output must not double-count the overlap.
    r = PIIRedactor()
    src = "visit https://site.test/path"
    redacted, mapping = r.redact(src)
    # Exactly one placeholder for this region.
    assert sum(1 for k in mapping if k.startswith("<")) == 1


def test_detect_returns_matches_in_document_order() -> None:
    r = PIIRedactor()
    src = "first a@b.com then 555-123-4567"
    detections = r.detect(src)
    starts = [d.start for d in detections]
    assert starts == sorted(starts)
