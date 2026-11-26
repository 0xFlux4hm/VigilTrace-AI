#!/usr/bin/env python3
"""phases.py — the mission phase ladder (thin module).

The linear five-phase skill ladder the orchestrator drives the agent through:

    0-bootstrap → 1-recon → 2-prioritize → 3-test → 4-validate → 5-report

Phase logic (validation of a requested phase, transitions via
mission_control action=phase, the phase recorded at mission_init) lives in
engine.py — MissionCore raises MissionError on a phase outside PHASES. This
module exists so the vocabulary has one home and can be imported without
pulling in the engine.
"""
from __future__ import annotations

PHASES = ["0-bootstrap", "1-recon", "2-prioritize", "3-test", "4-validate", "5-report"]
