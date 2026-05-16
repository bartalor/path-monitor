"""End-to-end: induce packet loss → LossDetector fires."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_loss_detection_fires_on_induced_loss(harness):
    # Let baseline probes flow briefly so the analyzer is rolling.
    harness.wait_for_alert("loss", timeout_s=2.0)  # don't expect one yet, just settle
    assert harness.alerts_of_type("loss") == []

    harness.sandbox.inject_loss(0.5)

    alert = harness.wait_for_alert("loss", timeout_s=30.0)
    assert alert is not None, (
        f"expected a `loss` alert within 30s of injecting 50% loss; "
        f"all alerts so far: {harness.all_alerts()}"
    )
    _, _, _, alert_type, _ = alert
    assert alert_type == "loss"
