"""Behavioural / session layer (V2).

Per-prompt detectors are blind to patterns over time: 200 individually-innocent
customer lookups that together assemble a book, a Support user who suddenly sweeps
KYC at 2am, escalating probing after repeated blocks. For an AML product that is
*the* attack. This package tracks a rolling per-user window and flags anomalies —
the one control no per-prompt classifier can provide.

``BehaviourTracker`` is the stateful core; ``behaviour_stage`` (in factory) adapts
it to the pipeline. It is a bare stage, NOT a BaseDetector — detectors are required
to be stateless, and behaviour is inherently stateful.
"""

from app.pdp.behaviour.tracker import BehaviourTracker, BehaviourVerdict

__all__ = ["BehaviourTracker", "BehaviourVerdict"]
