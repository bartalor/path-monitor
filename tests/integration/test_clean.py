"""End-to-end: no faults injected → no alerts fire."""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.integration


def test_no_alerts_on_clean_network(harness):
    time.sleep(15.0)
    alerts = harness.all_alerts()
    assert alerts == [], f"expected zero alerts on a clean network, got: {alerts}"
