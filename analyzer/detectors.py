from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from common.status import Status


@dataclass
class Alert:
    target_id: int
    timestamp_us: int
    type: str
    details: str


@dataclass
class RttDetector:
    window: int = 60
    z_threshold: float = 3.0
    samples: deque[float] = field(default_factory=deque)

    def observe(self, target_id: int, ts_us: int, rtt_us: int | None) -> Alert | None:
        if rtt_us is None or rtt_us < 0:
            return None
        x = float(rtt_us)
        # Need a baseline before detecting; populate the window first.
        if len(self.samples) < self.window:
            self.samples.append(x)
            return None

        mean = sum(self.samples) / len(self.samples)
        var = sum((s - mean) ** 2 for s in self.samples) / len(self.samples)
        std = math.sqrt(var)
        self.samples.append(x)
        if len(self.samples) > self.window:
            self.samples.popleft()

        if std <= 0:
            return None
        z = (x - mean) / std
        if z >= self.z_threshold:
            return Alert(
                target_id=target_id,
                timestamp_us=ts_us,
                type="rtt_spike",
                details=f"rtt_us={int(x)} mean={mean:.0f} std={std:.0f} z={z:.2f}",
            )
        return None


@dataclass
class LossDetector:
    window: int = 30
    threshold: float = 0.10
    outcomes: deque[bool] = field(init=False)  # True = lost
    fired: bool = False

    def __post_init__(self) -> None:
        self.outcomes = deque(maxlen=self.window)

    def observe(self, target_id: int, ts_us: int, status: str) -> Alert | None:
        lost = status != Status.OK
        self.outcomes.append(lost)
        if len(self.outcomes) < self.window:
            return None
        rate = sum(self.outcomes) / len(self.outcomes)
        if rate >= self.threshold and not self.fired:
            self.fired = True
            return Alert(
                target_id=target_id,
                timestamp_us=ts_us,
                type="loss",
                details=f"loss_rate={rate:.2%} window={self.window}",
            )
        if rate < self.threshold / 2:
            self.fired = False
        return None


@dataclass
class PathChangeDetector:
    last_hash: str | None = None

    def observe(self, target_id: int, ts_us: int, path_hash: str | None) -> Alert | None:
        if path_hash is None or path_hash == self.last_hash:
            return None
        prev, self.last_hash = self.last_hash, path_hash
        if prev is None:
            return None
        return Alert(
            target_id=target_id,
            timestamp_us=ts_us,
            type="path_change",
            details=f"from={prev} to={path_hash}",
        )


def drain(*alerts: Alert | None) -> Iterable[Alert]:
    return (a for a in alerts if a is not None)
