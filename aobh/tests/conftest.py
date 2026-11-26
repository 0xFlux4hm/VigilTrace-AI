"""Shared pytest fixtures for the AOBH test suite.

The five engine suites were ported from harnesses that each set their own
environment (BURP_*, ATAP_*, WAF_*, CAPTCHA_*, H1_*). Each suite passes alone
but bleeds state into siblings when run together; every test now runs against
a snapshot of the environment that is restored afterwards, and the tool
registry caches are dropped so the next test rebuilds them from fresh env.
"""

import os

import pytest


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
