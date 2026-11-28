"""Shared pytest fixtures for the AOBH test suite.

The five engine suites were ported from harnesses that each set their own
environment (BURP_*, ATAP_*, WAF_*, CAPTCHA_*, H1_*). Each suite passes alone
but bleeds state into siblings when run together; every test now runs against
a snapshot of the environment that is restored afterwards, and the tool
registry caches are dropped so the next test rebuilds them from fresh env.
"""

import os
import sys
from pathlib import Path

import pytest

# The working tree must always win over any installed/stale copy of this
# package (an older drop can sit elsewhere on sys.path via site init).
_REPO = str(Path(__file__).resolve().parent.parent)
if _REPO in sys.path:
    sys.path.remove(_REPO)
sys.path.insert(0, _REPO)

# Pre-seed the parent package from the working tree: submodule imports then
# resolve through aobh.__path__ (repo) even if something else shuffles
# sys.path afterwards (a stale copy of this project exists elsewhere).
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "aobh", str(Path(_REPO) / "aobh" / "__init__.py"))
_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("aobh", _mod)
_spec.loader.exec_module(sys.modules["aobh"])


@pytest.fixture(autouse=True)
def _isolate_env_and_registry():
    before = dict(os.environ)
    try:
        from aobh.tools import registry

        registry.reset()
        yield
        registry.reset()
    except Exception:
        yield
    finally:
        os.environ.clear()
        os.environ.update(before)
