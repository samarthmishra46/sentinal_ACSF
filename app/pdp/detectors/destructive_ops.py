"""Destructive data-operation detector — Stage 9 (Samarth · Day-5).

Closes a coverage gap found in testing: "delete person on database for this
PAN ..." and "delete all customer records" both passed clean, because no V1 rule
covered *destructive data modification*. The intent scanner (R-02..R-09) targets
specific AML-compliance patterns, not "wipe the customer table".

Two-part matcher, mirroring the intent scanner's style: a destructive VERB
(delete / drop / truncate / wipe / purge / erase / destroy) co-occurring with a
data OBJECT (customer / person / record / account / table / database / KYC / CDD
...). Both must be present, so "delete a temp file" or "remove this comment"
does not fire.

Disposition is **ESCALATE**, not STOP: deleting records can be legitimate ops or
data-erasure (DPDP/GDPR) work, so a human decides — and each review becomes a
labelled example. Rule R-21 / policy P-21 (see policies/v1/catalog.yaml).

Runs at stage_order 9 — after every other detector — so a prompt that also
leaks PII (e.g. a PAN) still STOPs earlier at Stage 6 (stricter wins); this
detector is the backstop for destructive intent with no other signal.

Owner: Samarth   Rule: R-21
"""

from __future__ import annotations

import re

from app.identity.context import RequestContext
from app.pdp.decision import Disposition, Signal
from app.pdp.detectors.base import BaseDetector
from app.policy.models import Snapshot

# Destructive verbs, including common SQL forms (DROP TABLE, DELETE FROM).
_DESTRUCTIVE_VERB = re.compile(
    r"\b(delete|drop|truncate|wipe|purge|erase|destroy|obliterate|"
    r"delete\s+from|drop\s+table)\b",
    re.IGNORECASE,
)

# Data / person objects that make a destructive verb dangerous. Generic targets
# only (customer, person, record, account, table, database, KYC/CDD artefacts).
_DATA_OBJECT = re.compile(
    r"\b(customers?|persons?|people|clients?|users?|accounts?|records?|"
    r"rows?|tables?|databases?|db|kyc|cdd|profiles?|entr(?:y|ies))\b",
    re.IGNORECASE,
)

# Filesystem targets. Destructive verbs against these are also held for review —
# "truncate the files in the folder", "wipe the disk". Scoped to *bulk/whole*
# targets (plural files, a folder/directory/disk/filesystem) so a single "delete
# the temp file" stays quiet; deleting many files or a whole tree does not.
_FILESYSTEM_OBJECT = re.compile(
    r"\b(files|folders?|director(?:y|ies)|disks?|filesystems?|"
    r"file\s+system|volumes?|partitions?|"
    r"(?:everything|all|every\s+file)\s+in\s+(?:the\s+)?(?:folder|directory|dir))\b",
    re.IGNORECASE,
)


class DestructiveOpsDetector(BaseDetector):
    """Stage 9: destructive data operations on customer/person data -> ESCALATE."""

    @property
    def stage_name(self) -> str:
        return "destructive_ops_scanner"

    @property
    def stage_order(self) -> int:
        return 9  # after ML (8): backstop for destructive intent with no other signal

    def scan(self, ctx: RequestContext, prompt: str, snap: Snapshot) -> Signal | None:
        """ESCALATE when a destructive verb co-occurs with a data/person object."""
        try:
            return self._detect(prompt)
        except Exception:  # never raise out of a detector (BaseDetector contract)
            return None

    def _detect(self, prompt: str) -> Signal | None:
        verb = _DESTRUCTIVE_VERB.search(prompt)
        obj = _DATA_OBJECT.search(prompt)
        target = "data"
        if not (verb and obj):
            # No data/person object — try filesystem targets (bulk file/dir/disk
            # destruction). Same verb set, ESCALATE for the same reason: a human
            # confirms a mass-delete was intended and authorised.
            obj = _FILESYSTEM_OBJECT.search(prompt)
            target = "filesystem"
        if not (verb and obj):
            return None

        detail = (
            "deletion of customer data must be authorised." if target == "data"
            else "bulk file/directory destruction must be authorised."
        )
        return Signal(
            detector=self.stage_name,
            rule_id="R-21",
            disposition=Disposition.ESCALATE,
            reason=(
                f"Destructive {target} operation detected: '{verb.group(0).lower()}' "
                f"targeting '{obj.group(0).lower()}'. Held for human review — {detail}"
            ),
            confidence=0.8,
            metadata={
                "owasp_id": "LLM06",
                "atlas_id": "AML.T0040",
                "severity": "HIGH",
                "verb": verb.group(0).lower(),
                "object": obj.group(0).lower(),
                "target_class": target,
            },
        )
