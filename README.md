# Path Monitor

Continuous network path monitoring and anomaly detection. Probes a configurable list of targets with ICMP and traceroute, stores measurements in SQLite, and flags latency spikes, packet loss events, and route changes in near real-time.

## Components

### Prober ([prober/](prober/))
- Raw ICMP socket, hand-rolled packet build/parse (RFC 792)
- TTL-limited ICMP traceroute
- Thread pool for parallel probes, dedicated SQLite writer thread
- YAML config; per-target ICMP identifier + per-probe sequence to disambiguate replies

### Analyzer ([analyzer/](analyzer/))
- Reads SQLite, runs detectors in a poll loop
- RTT z-score, sliding-window loss rate, path-hash change detection
- Pluggable sinks: stdout, file, TCP

### Orchestrator ([orchestrator/](orchestrator/))
- CLI: `init-db`, `run`
- Process supervisor with exponential backoff and signal propagation

### Storage ([sql/schema.sql](sql/schema.sql))
Tables: `targets`, `probes`, `paths`, `alerts`. Indexed on `(target_id, timestamp)`, `(path_hash)`, `(alerts.timestamp)`.

## Layout
```
prober/        Python prober (raw ICMP, traceroute, SQLite writer)
analyzer/      Python analyzer (detectors, sinks)
orchestrator/  Python supervisor + CLI
scripts/       Bash: setup, scenario_loss, scenario_route_change, deploy
config/        YAML config
sql/           Schema
data/          SQLite DB (gitignored)
logs/          Runtime logs (gitignored)
```

## Setup
```
pip install -r requirements.txt
python -m orchestrator init-db --config config/path_monitor.yaml
sudo setcap cap_net_raw=eip "$(readlink -f $(which python3))"   # or use scripts/deploy.sh
python -m orchestrator run --config config/path_monitor.yaml
```

## Validation
- Probe several public targets (DNS providers, gateway) for a few hours
- Inject 20% loss: `sudo scripts/scenario_loss.sh 8.8.8.8 60 0.2`
- Change route: `sudo scripts/scenario_route_change.sh 8.8.8.8 <alt-gw> 60`
- Verify ICMP bytes against RFC 792 with `tcpdump -nni any icmp` and Wireshark
- Inspect socket / interface state with `ss -nlp`, `netstat -i`

## Tech stack
Python 3 (stdlib `socket`, `struct`, `sqlite3`, `concurrent.futures`, `threading`), PyYAML, SQLite, Bash, iptables, tcpdump, Wireshark, ip, ss, netstat.
