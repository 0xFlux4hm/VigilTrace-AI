"""orchestrator — the mission control engine: lifecycle, task DAG, coverage,
memory, budget, approvals, triggers, phases and the adversarial validator.

Public surface:
  MissionCore / Orchestrator  the engine (aobh.orchestrator.engine)
  MissionStore                persistence (aobh.orchestrator.store)
  MissionError / MissionStoreError
  register(engagement_dir)    the 14-tool handler map for manifest group
                              "mission_control" (aobh.orchestrator.tools)
  validator                   kill-test planning, evidence scoring, dedup
  dag / triggers / coverage / budget / approvals / memory / phases
                              engine internals, split 1:1 from the proven core
"""
from aobh.orchestrator.engine import MissionCore, MissionError, Orchestrator
from aobh.orchestrator.store import MissionStore, MissionStoreError
from aobh.orchestrator.tools import register

__all__ = [
    "MissionCore",
    "MissionError",
    "MissionStore",
    "MissionStoreError",
    "Orchestrator",
    "register",
]
