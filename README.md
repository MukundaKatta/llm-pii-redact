# llm-pii-redact

[![PyPI](https://img.shields.io/pypi/v/llm-pii-redact.svg)](https://pypi.org/project/llm-pii-redact/)
[![Python](https://img.shields.io/pypi/pyversions/llm-pii-redact.svg)](https://pypi.org/project/llm-pii-redact/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Regex-based PII redaction for LLM prompts.**

Before you send user text to a third-party LLM, swap out personal data
for stable placeholders. After the model returns, swap the originals
back in. The library is plain Python with zero runtime dependencies.

Detectors built in: `EMAIL`, `PHONE_US`, `SSN`, `CREDIT_CARD` (with Luhn
check), `IP_V4`, `IP_V6`, `IBAN`, `URL`.

## Install

```bash
pip install llm-pii-redact
```

## Basic example

```python
from llm_pii_redact import PIIRedactor

redactor = PIIRedactor()
redacted, mapping = redactor.redact(
    "Email me at john@example.com or call 555-123-4567"
)
# redacted == "Email me at <EMAIL_0> or call <PHONE_US_0>"
# mapping  == {"<EMAIL_0>": "john@example.com", "<PHONE_US_0>": "555-123-4567"}
```

The same value always gets the same placeholder, so two passes over the
same input produce the same redacted text.

## Restore round trip

Send the redacted text to the LLM. When the response comes back, swap
the placeholders out for the original values:

```python
answer = call_llm(redacted)              # answer might reference <EMAIL_0>
final  = redactor.restore(answer, mapping)
```

`restore` is the inverse of `redact`. Unknown placeholders in the
response are left alone, and longer placeholder names are replaced first
so `<EMAIL_10>` does not collide with `<EMAIL_1>`.

## Pick a subset of detectors

```python
from llm_pii_redact import PIIRedactor, PIIType

only_contact = PIIRedactor(types={PIIType.EMAIL.value, PIIType.PHONE_US.value})
```

Pass type names as strings (`"EMAIL"`) or via the `PIIType` enum.

## Custom pattern

Register your own regex if you need to redact vendor-specific shapes
such as API keys:

```python
redactor.add_pattern("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}")
redacted, mapping = redactor.redact("key=AKIAABCDEFGHIJKLMNOP")
# redacted == "key=<AWS_ACCESS_KEY_0>"
```

Custom names follow the same `<NAME_0>`, `<NAME_1>`, ... convention.

## Inspect without modifying

```python
for d in redactor.detect("contact ops@example.com"):
    print(d.type, d.value, d.start, d.end)
```

`detect` returns a list of `Detection` dataclasses in document order
with no rewriting.

## Type reference

| Type | What it matches |
| --- | --- |
| `EMAIL` | RFC 5322 subset, e.g. `name.tag+filter@host.example` |
| `PHONE_US` | 10 or 11 digit US numbers, with or without `+1`, parens, dashes, dots |
| `SSN` | `XXX-XX-XXXX` or 9 contiguous digits |
| `CREDIT_CARD` | 13-19 digits with optional spaces or dashes, validated by Luhn |
| `IP_V4` | Four octets 0-255 |
| `IP_V6` | Standard or compressed forms with `::` |
| `IBAN` | Two-letter country, two check digits, 11-30 alphanumerics |
| `URL` | `http://` or `https://` followed by host and path |

## What it does NOT do

- No machine learning. Pure regex. Adversarially crafted text will slip
  through. Treat this as defense in depth, not a complete privacy layer.
- No network calls. No telemetry.
- No language detection. The patterns target North American and common
  international formats.
- No file or attachment handling. Pass it strings only.

## Related libraries

If you also need to keep the LLM's response under a size cap, see the
sibling library
[`tool-output-truncate-py`](https://pypi.org/project/tool-output-truncate-py/).

## License

MIT
