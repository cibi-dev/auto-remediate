"""Submódulo de clasificación y triaje de vulnerabilidades."""

from auto_remediate.classifier.triage_engine import TriagedFinding, TriageEngine

__all__ = ["TriageEngine", "TriagedFinding"]
