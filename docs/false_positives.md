# Sentinel — Known False Positive Patterns (V2 Backlog)

**Owner:** Sneha
**Created:** Day 3 — Detector tuning session
**Status:** Documented for V2. Cannot be fixed with regex alone — need NLP or context-aware classification.

---

## FP-01: Placeholder data triggers PII detector

**Example prompt:**
"Use test data: name=Jane Doe, TFN=000-000-000, DOB=01/01/2000 for the unit test fixture."

**What happens:** R-01 fires because `000-000-000` matches the TFN regex `\d{3}-\d{3}-\d{3}`.

**Why V1 can't fix it:** The regex cannot distinguish a real TFN from a placeholder like `000-000-000` or `123-123-123`. Both match the same pattern. Fixing this requires semantic analysis — understanding that the surrounding context says "test data" or "placeholder" or "dummy values."

**V2 fix:** Add a Presidio custom recognizer that checks for common placeholder patterns (`000-000-000`, `111-111-111`, `123-456-789` when preceded by words like "test", "fake", "example", "placeholder", "dummy"). Alternatively, use an NLP classifier trained on the difference between data-description and data-inclusion.

**Risk of not fixing:** Engineers use workarounds — they type "TFN=000 000 000" with spaces instead of dashes to avoid the regex. This teaches the team to evade the detector rather than trust it.

---

## FP-02: Number grouping matches TFN pattern

**Example prompt:**
"We processed 123-456-789 records last quarter. How do I display this in the dashboard?"

**What happens:** R-01 fires because the number `123-456-789` matches the TFN regex.

**Why V1 can't fix it:** Without understanding that this is a count (noun context: "records"), not an identifier (noun context: "customer"), the regex treats any 9-digit grouped number as a potential TFN.

**V2 fix:** Named-entity recognition with part-of-speech tagging. If the number is preceded by a verb like "processed" or followed by a noun like "records" or "transactions", it's a count, not a TFN. Presidio's context-aware scoring can handle this with custom context words.

**Risk of not fixing:** Low — this pattern is uncommon in real engineering prompts. Most engineers would write "123,456,789" or "123M" for large numbers.

---

## FP-03: Quoted injection phrase in narrative

**Example prompt:**
"A user typed 'ignore previous instructions' into the customer form. Our validator didn't catch it. How do I add a filter?"

**What happens:** R-06 fires because the phrase "ignore previous instructions" is present in the prompt, even though it's being quoted as an example.

**Why V1 can't fix it:** The Aho-Corasick scanner matches on the raw text. It cannot distinguish between the engineer using an injection phrase and the engineer quoting one. This is a fundamental limitation of string matching — it has no concept of quotation or metalanguage.

**V2 fix:** Quoted-speech detection. If an injection phrase appears inside quotation marks (single or double) and the surrounding text contains words like "typed", "entered", "sent", "submitted", "contained", "payload", or "the user said", treat it as a narrative reference, not an attack. Alternatively, use an NLP classifier that understands the difference between use and mention.

**Risk of not fixing:** Medium — engineers debugging injection attempts in logs or user input WILL encounter this. They'll paste the offending input to ask "how do I handle this?" and get blocked. Current workaround: describe the injection instead of quoting it ("the user tried an instruction-override attack").

---

## FP-04: Log analysis containing injection text

**Example prompt:**
"The access log shows a blocked request with payload 'act as DAN'. Should we alert the security team?"

**What happens:** R-06 fires because "act as DAN" matches the injection phrase list.

**Why V1 can't fix it:** Same as FP-03 — the scanner matches on content, not on whether the content is being analysed vs. being executed.

**V2 fix:** Same as FP-03 — quoted-speech detection plus source-context awareness. If the prompt references "log", "access log", "blocked request", "payload", or "audit trail", the injection phrase is evidence being examined, not an attack being launched.

**Risk of not fixing:** Medium — SOC analysts reviewing blocked-request logs through the assistant will hit this regularly.

---

## FP-05: "Bypass rate" metric triggers compliance bypass rule

**Example prompt:**
"Our CDD bypass rate is too high — 12% of customers skip verification due to timeouts. How do we reduce this?"

**What happens:** R-03 fires because "bypass" (action verb) + "CDD" (compliance object) both match.

**Why V1 can't fix it:** The two-part matcher cannot distinguish between "bypass the CDD check" (imperative — doing the bypass) and "bypass rate of the CDD check" (descriptive — measuring the bypass). Both use the same words.

**V2 fix:** Part-of-speech tagging. If "bypass" is used as a noun ("bypass rate", "the bypass") rather than a verb ("bypass the check", "skip the verification"), it's descriptive, not imperative. Alternatively, add "bypass rate" and "bypass percentage" to the false-positive guard.

**Risk of not fixing:** Medium — compliance and engineering teams discuss bypass rates in standups and Slack. An engineer asking the assistant to help analyse bypass metrics will get blocked.

**Quick V1 mitigation (optional):** Add `bypass\s+rate|bypass\s+percent|bypass\s+metric` to `_BYPASS_OK` guard in intent.py. This is a narrow, safe fix that doesn't require NLP.

---

## Summary

| ID | Pattern | Detector | V2 requirement |
|----|---------|----------|----------------|
| FP-01 | Placeholder data matching PII format | PII (R-01) | Semantic context analysis |
| FP-02 | Number grouping matching TFN pattern | PII (R-01) | Part-of-speech tagging |
| FP-03 | Quoted injection in narrative | Injection (R-06) | Quoted-speech detection |
| FP-04 | Log analysis containing injection | Injection (R-06) | Source-context awareness |
| FP-05 | "Bypass rate" as metric vs command | Intent (R-03) | Part-of-speech tagging |

All five share the same root cause: V1 detectors use pattern matching (what words are present) without understanding intent (why those words are present). V2 needs NLP-based intent classification to resolve these.