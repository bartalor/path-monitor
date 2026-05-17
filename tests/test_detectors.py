import random

from analyzer.detectors import LossDetector, PathChangeDetector, RttDetector
from common.status import Status


def test_rtt_detector_fires_on_zscore():
    rng = random.Random(0)
    d = RttDetector(window=20, z_threshold=3.0)
    for i in range(40):
        d.observe(1, i, 1000 + rng.randint(-50, 50))
    alert = d.observe(1, 100, 50_000)
    assert alert is not None
    assert alert.type == "rtt_spike"


def test_rtt_detector_silent_on_steady():
    d = RttDetector(window=10, z_threshold=3.0)
    for i in range(50):
        # Constant samples → std=0 → no alert (degenerate baseline).
        assert d.observe(1, i, 1000) is None


def test_loss_detector_fires_once():
    d = LossDetector(window=10, threshold=0.2)
    # Fill window with successes first.
    for i in range(9):
        assert d.observe(1, i, Status.OK) is None
    # First sample that pushes loss rate to threshold.
    a = d.observe(1, 9, Status.TIMEOUT)
    # Either the previous step or a follow-up fills the window and fires once.
    if a is None:
        a = d.observe(1, 10, Status.TIMEOUT)
    assert a is not None
    assert a.type == "loss"
    # Does not re-fire while still above threshold.
    assert d.observe(1, 11, Status.TIMEOUT) is None


def test_path_change_detector():
    d = PathChangeDetector()
    assert d.observe(1, 0, "h1") is None
    a = d.observe(1, 1, "h2")
    assert a is not None
    assert a.type == "path_change"
    # Same hash → silent.
    assert d.observe(1, 2, "h2") is None
