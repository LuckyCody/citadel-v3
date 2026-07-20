# Citadel self-validation clock

This directory contains the Packet 009 time-gate runner. It does not compress
calendar time and it does not turn a smoke test into a soak receipt.

```bash
python3 validation/pilot_v1/pilot.py freeze

# Mechanical smoke test only (never qualifying):
python3 validation/pilot_v1/pilot.py run --phase soak --test-mode \
  --duration-seconds 10 --sample-interval 1 --judge-interval 0 \
  --state-dir /tmp/citadel-pilot-smoke

# Real seven-day gate, detached and resumable evidence on the Ubuntu filesystem:
python3 validation/pilot_v1/pilot.py start --phase soak
python3 validation/pilot_v1/pilot.py status --phase soak

# This command refuses to start until the qualifying soak summary is green:
python3 validation/pilot_v1/pilot.py start --phase pilot
```

Generated root/API credentials and mutable runtime state live outside the repo at
`~/.local/state/citadel-pilot-v1` with owner-only permissions. They are never
included in the evidence bundle. Source drift, API death, health failure, daily
judge failure, or sample-chain corruption prevents a qualifying pass.
