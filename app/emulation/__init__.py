"""Adversary emulation module — threat actor profiles, plans, and execution.

Closes the purple-team loop with the detection pipeline: emulate known actor
TTPs against a customer environment, then validate which techniques the
existing Splunk detections caught.
"""
from app.emulation.schema import init_emulation_schema

__all__ = ["init_emulation_schema"]
