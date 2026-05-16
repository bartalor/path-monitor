"""End-to-end: inject latency spike → RttDetector fires."""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.integration


def test_rtt_spike_fires_on_induced_latency(harness):
    # Fill the RTT baseline window with healthy samples first.
    # window=20, probe_interval=200ms → ~5s to fill comfortably.
    time.sleep(8.0)
    assert harness.alerts_of_type("rtt_spike") == []

    harness.sandbox.inject_delay_ms(500)

    alert = harness.wait_for_alert("rtt_spike", timeout_s=20.0)
    assert alert is not None, (
        f"expected an `rtt_spike` alert within 20s of injecting 500ms delay; "
        f"all alerts so far: {harness.all_alerts()}"
    )
