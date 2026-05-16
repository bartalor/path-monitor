# path-monitor

Project for continuous network path monitoring: a prober sends ICMP echo + traceroute to a list of targets, writes results to SQLite; an analyzer reads SQLite and fires alerts on RTT spikes, packet loss, and path changes; an orchestrator supervises both as subprocesses.

## Raw ICMP requires privilege

The prober opens `SOCK_RAW` / `IPPROTO_ICMP`. Two ways to make that work:
- `sudo` the process, or
- `sudo setcap cap_net_raw=eip "$(readlink -f "$(which python3)")"` once (see [README.md](README.md)).

Unit tests don't need either — they parse/build packets in memory. Integration tests need real raw sockets and a netns, so they're root-only.

## Tests: two modes

Default `pytest` runs unit tests only. Integration tests are gated by a marker, deselected by `addopts` in [pyproject.toml](pyproject.toml):

```
pytest                              # unit only (fast, no privileges)
sudo -E pytest -m integration       # full pipeline in a netns
```

`sudo -E` matters — it preserves `PYTHONPATH` and the pyenv-selected interpreter. Plain `sudo pytest` will fail with "command not found" because sudo resets PATH.

## Integration harness ([tests/integration/](tests/integration/))

Linux-only, root-only. Skips cleanly elsewhere via `_skip_if_unsupported()` in [tests/integration/netns.py](tests/integration/netns.py).

Topology per test:
- One network namespace (`pm-<6hex>`), one veth pair, /30 on `10.255.<rand>.0/30`.
- A tiny ICMP echo responder ([tests/integration/responder.py](tests/integration/responder.py)) runs inside the netns. It reuses `prober.icmp_packet` primitives so we test the same parser the prober uses.
- The orchestrator runs on the host side and probes the responder.
- Faults are injected with `tc netem` on the host-side veth (`inject_loss`, `inject_delay_ms`, `clear_faults`).

The `harness` fixture in [tests/integration/conftest.py](tests/integration/conftest.py) wires this together, writes a per-test config to `tmp_path`, runs `init-db`, then `Popen`s the orchestrator. Teardown is SIGTERM → 5s → SIGKILL, then netns/veth cleanup.

If a test hangs, the responder or orchestrator subprocess is probably wedged — check `ip netns list` and `ps -ef | grep pm-` for leftover state from a crashed test.

## Path-change integration test is deferred

We intentionally did NOT write `test_path_change_detection`. It needs a 3-namespace topology (source → middle hop → target) with route flipping, which is a different shape from the current single-netns harness. Per Rule of Three, we'll generalize the harness when there's a third use case, not preemptively.
