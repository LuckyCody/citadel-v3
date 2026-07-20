#!/usr/bin/env python3
"""Resumable, hash-bound Citadel local soak/pilot runner.

This runner cannot compress calendar time. `--test-mode` exercises mechanics but
produces a non-qualifying summary. A qualifying pilot cannot start until a real
seven-day soak summary has passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).resolve().parent / "candidate_manifest.json"
SOAK_SECONDS = 7 * 24 * 60 * 60
PILOT_SECONDS = 30 * 24 * 60 * 60
DEFAULT_STATE = Path.home() / ".local/state/citadel-pilot-v1"
EXCLUDED_PARTS = {".git", "target", "__pycache__", "pilot_v1"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def candidate_files() -> list[Path]:
    files: list[Path] = []
    for directory, names, filenames in os.walk(ROOT):
        names[:] = [name for name in names if name not in EXCLUDED_PARTS]
        base = Path(directory)
        for filename in filenames:
            path = base / filename
            if path.suffix in {".rs", ".toml", ".lock", ".md", ".yaml", ".yml", ".sh"}:
                files.append(path)
    return sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())


def source_inventory() -> tuple[str, list[dict[str, object]]]:
    inventory = []
    aggregate = hashlib.sha256()
    for path in candidate_files():
        relative = path.relative_to(ROOT).as_posix()
        digest = sha256_file(path)
        size = path.stat().st_size
        inventory.append({"path": relative, "sha256": digest, "bytes": size})
        aggregate.update(relative.encode())
        aggregate.update(b"\0")
        aggregate.update(digest.encode())
        aggregate.update(b"\n")
    return aggregate.hexdigest(), inventory


def run_checked(command: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr[-2000:]}"
        )
    return result.stdout


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def freeze() -> None:
    digest, inventory = source_inventory()
    metadata = json.loads(run_checked([cargo(), "metadata", "--locked", "--offline", "--format-version", "1"]))
    manifest = {
        "schema_version": 1,
        "classification": "self-validated-audit-candidate-pending-time-gates",
        "frozen_at_utc": utc_now(),
        "git_revision": git_value(["rev-parse", "HEAD"]),
        "git_diff_sha256": hashlib.sha256(
            subprocess.run(
                ["git", "diff", "--binary", "HEAD"], cwd=ROOT, stdout=subprocess.PIPE, check=False
            ).stdout
        ).hexdigest(),
        "source_inventory_sha256": digest,
        "cargo_lock_sha256": sha256_file(ROOT / "Cargo.lock"),
        "workspace_packages": sorted(package["name"] for package in metadata["packages"]),
        "files": inventory,
        "required_real_time_seconds": {"soak": SOAK_SECONDS, "pilot": PILOT_SECONDS},
        "nonclaims": [
            "not independently audited",
            "not FIPS 140 validated",
            "not hardware-backed custody",
            "not native-Windows validated",
            "not unrestricted production",
        ],
    }
    atomic_json(MANIFEST, manifest)
    print(json.dumps({"status": "frozen", "source_inventory_sha256": digest}, indent=2))


def cargo() -> str:
    configured = os.environ.get("CARGO_BIN")
    if configured:
        return configured
    home = Path.home() / ".cargo/bin/cargo"
    return str(home if home.exists() else "cargo")


def git_value(args: list[str]) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, text=True, stdout=subprocess.PIPE, check=False)
    return result.stdout.strip() or "unavailable"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_mode(path: Path, mode: int) -> None:
    path.chmod(mode)
    if stat.S_IMODE(path.stat().st_mode) != mode:
        raise RuntimeError(f"could not set {path} to mode {mode:o}")


def allocate_port(preferred: int) -> int:
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])


def phase_paths(state: Path, phase: str) -> dict[str, Path]:
    phase_dir = state / phase
    return {
        "phase": phase_dir,
        "config": phase_dir / "config.json",
        "samples": phase_dir / "samples.jsonl",
        "summary": phase_dir / "summary.json",
        "pid": phase_dir / "runner.pid",
        "log": phase_dir / "runner.log",
        "api_log": phase_dir / "api.log",
    }


def append_sample(path: Path, record: dict) -> None:
    previous = "0" * 64
    if path.exists():
        last = path.read_text(encoding="utf-8").splitlines()
        if last:
            previous = json.loads(last[-1])["record_hash"]
    record["previous_hash"] = previous
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    record["record_hash"] = hashlib.sha256(canonical).hexdigest()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def validate_chain(path: Path) -> tuple[bool, int]:
    previous = "0" * 64
    count = 0
    for raw in path.read_text(encoding="utf-8").splitlines() if path.exists() else []:
        record = json.loads(raw)
        claimed = record.pop("record_hash")
        if record.get("previous_hash") != previous:
            return False, count
        actual = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if actual != claimed:
            return False, count
        previous = claimed
        count += 1
    return True, count


def pilot_env(state: Path, port: int) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "CITADEL_PROFILE": "local-pilot",
            "CITADEL_ROOT_KEY_FILE": str(state / "custody/root.key"),
            "CITADEL_ENV": "pilot",
            "CITADEL_REPLAY_STORE": "file",
            "CITADEL_REPLAY_STORE_PATH": str(state / "replay.json"),
            "CITADEL_API_KEY_HASH": (state / "api-key.hash").read_text().strip(),
            "CITADEL_DATA_DIR": str(state / "data"),
            "CITADEL_SEED_DEMO": "false",
            "CITADEL_PORT": str(port),
        }
    )
    for forbidden in (
        "CITADEL_MASTER_KEY",
        "CITADEL_API_KEY",
        "CITADEL_ALLOW_PLAINTEXT_KEYS",
        "CITADEL_ALLOW_FLAT_DEKS",
    ):
        env.pop(forbidden, None)
    return env


def initialize_state(state: Path) -> None:
    state.mkdir(parents=True, exist_ok=True)
    ensure_mode(state, 0o700)
    custody = state / "custody"
    custody.mkdir(exist_ok=True)
    ensure_mode(custody, 0o700)
    root_key = custody / "root.key"
    root_cli = ROOT / "target/debug/citadel-root-key"
    hash_cli = ROOT / "target/debug/hash-apikey"
    api = ROOT / "target/debug/citadel-api"
    run_checked([cargo(), "build", "--locked", "--offline", "-p", "citadel-keystore", "--bin", "citadel-root-key"])
    run_checked([cargo(), "build", "--locked", "--offline", "-p", "citadel-api", "--bins"])
    if not root_key.exists():
        run_checked([str(root_cli), "init", str(root_key)])
    run_checked([str(root_cli), "check", str(root_key)])
    api_key_path = state / "api-key.secret"
    if not api_key_path.exists():
        api_key_path.write_text(secrets.token_hex(32), encoding="ascii")
        ensure_mode(api_key_path, 0o600)
    base_env = os.environ.copy()
    base_env.update(
        {
            "CITADEL_PROFILE": "local-pilot",
            "CITADEL_ROOT_KEY_FILE": str(root_key),
            "CITADEL_ENV": "pilot",
            "CITADEL_REPLAY_STORE": "file",
        }
    )
    hashed = run_checked([str(hash_cli), api_key_path.read_text().strip()], env=base_env)
    hash_value = next(line[5:] for line in hashed.splitlines() if line.startswith("HASH:"))
    hash_path = state / "api-key.hash"
    hash_path.write_text(hash_value + "\n", encoding="ascii")
    ensure_mode(hash_path, 0o600)
    if not api.exists():
        raise RuntimeError("citadel-api build did not produce an executable")


def start_api(paths: dict[str, Path], env: dict[str, str]) -> subprocess.Popen:
    log = paths["api_log"].open("ab", buffering=0)
    return subprocess.Popen(
        [str(ROOT / "target/debug/citadel-api")],
        cwd=ROOT,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def health(port: int) -> tuple[bool, int]:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
            ok = response.status == 200
    except Exception:
        ok = False
    return ok, int((time.monotonic() - started) * 1000)


def run_phase(args: argparse.Namespace) -> int:
    if not MANIFEST.exists():
        raise RuntimeError("candidate is not frozen; run `pilot.py freeze` first")
    manifest = load_json(MANIFEST)
    state = args.state_dir.resolve()
    paths = phase_paths(state, args.phase)
    paths["phase"].mkdir(parents=True, exist_ok=True)
    initialize_state(state)

    required = SOAK_SECONDS if args.phase == "soak" else PILOT_SECONDS
    if args.test_mode:
        duration = args.duration_seconds
    else:
        duration = required
        if args.duration_seconds is not None and args.duration_seconds != required:
            raise RuntimeError("qualifying phases use fixed real-time durations")
    if args.phase == "pilot" and not args.test_mode:
        soak_summary = phase_paths(state, "soak")["summary"]
        if not soak_summary.exists() or load_json(soak_summary).get("status") != "pass":
            raise RuntimeError("a qualifying seven-day soak must pass before the pilot starts")

    port = allocate_port(args.port)
    started = time.time()
    config = {
        "schema_version": 1,
        "phase": args.phase,
        "qualifying": not args.test_mode,
        "started_at_utc": utc_now(),
        "started_epoch": started,
        "deadline_epoch": started + duration,
        "required_duration_seconds": required,
        "planned_duration_seconds": duration,
        "sample_interval_seconds": args.sample_interval,
        "judge_interval_seconds": args.judge_interval,
        "port": port,
        "candidate_source_inventory_sha256": manifest["source_inventory_sha256"],
    }
    atomic_json(paths["config"], config)
    paths["pid"].write_text(str(os.getpid()), encoding="ascii")

    env = pilot_env(state, port)
    api = start_api(paths, env)
    failures = 0
    judge_index = 0
    next_judge = started + args.judge_interval if args.judge_interval else float("inf")
    try:
        while time.time() < config["deadline_epoch"]:
            source_digest, _ = source_inventory()
            alive = api.poll() is None
            ok, latency = health(port) if alive else (False, 0)
            source_match = source_digest == manifest["source_inventory_sha256"]
            if not (alive and ok and source_match):
                failures += 1
            append_sample(
                paths["samples"],
                {
                    "timestamp_utc": utc_now(),
                    "epoch": time.time(),
                    "api_alive": alive,
                    "health_ok": ok,
                    "health_latency_ms": latency,
                    "source_match": source_match,
                    "api_exit_code": api.poll(),
                },
            )
            if not alive:
                api = start_api(paths, env)
            if args.judge_interval and time.time() >= next_judge:
                judge_index += 1
                judge_dir = paths["phase"] / f"judge_{judge_index:03d}"
                result = subprocess.run(
                    [
                        "bash",
                        "scripts/test-citadel-ubuntu.sh",
                        "--runs",
                        "1",
                        "--receipt-dir",
                        str(judge_dir),
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=(paths["phase"] / f"judge_{judge_index:03d}.log").open("wb"),
                    stderr=subprocess.STDOUT,
                    check=False,
                )
                if result.returncode:
                    failures += 1
                next_judge = time.time() + args.judge_interval
            time.sleep(args.sample_interval)
    finally:
        if api.poll() is None:
            api.terminate()
            try:
                api.wait(timeout=10)
            except subprocess.TimeoutExpired:
                api.kill()
        paths["pid"].unlink(missing_ok=True)

    ended = time.time()
    chain_ok, samples = validate_chain(paths["samples"])
    elapsed = ended - started
    qualifying = not args.test_mode and elapsed >= required
    summary = {
        "schema_version": 1,
        "phase": args.phase,
        "classification": "qualifying" if qualifying else "non-qualifying-smoke",
        "status": "pass" if qualifying and failures == 0 and chain_ok else "smoke-pass" if failures == 0 and chain_ok else "fail",
        "started_epoch": started,
        "ended_epoch": ended,
        "elapsed_seconds": elapsed,
        "required_duration_seconds": required,
        "sample_count": samples,
        "failure_count": failures,
        "sample_chain_intact": chain_ok,
        "candidate_source_inventory_sha256": manifest["source_inventory_sha256"],
    }
    atomic_json(paths["summary"], summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if failures == 0 and chain_ok else 1


def start_detached(args: argparse.Namespace) -> None:
    paths = phase_paths(args.state_dir.resolve(), args.phase)
    paths["phase"].mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(Path(__file__).resolve()), "run", "--phase", args.phase,
               "--state-dir", str(args.state_dir), "--sample-interval", str(args.sample_interval),
               "--judge-interval", str(args.judge_interval), "--port", str(args.port)]
    if args.test_mode:
        command.extend(["--test-mode", "--duration-seconds", str(args.duration_seconds)])
    log = paths["log"].open("ab", buffering=0)
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(0.5)
    if process.poll() is not None:
        raise RuntimeError(f"runner exited immediately; inspect {paths['log']}")
    print(json.dumps({"status": "started", "pid": process.pid, "log": str(paths["log"])}))


def status(args: argparse.Namespace) -> None:
    paths = phase_paths(args.state_dir.resolve(), args.phase)
    config = load_json(paths["config"]) if paths["config"].exists() else None
    summary = load_json(paths["summary"]) if paths["summary"].exists() else None
    chain_ok, samples = validate_chain(paths["samples"])
    pid = int(paths["pid"].read_text()) if paths["pid"].exists() else None
    alive = False
    if pid:
        try:
            os.kill(pid, 0)
            alive = True
        except OSError:
            pass
    print(json.dumps({"running": alive, "pid": pid, "samples": samples,
                      "sample_chain_intact": chain_ok, "config": config, "summary": summary},
                     indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("freeze")
    for command in ("run", "start"):
        item = sub.add_parser(command)
        item.add_argument("--phase", choices=("soak", "pilot"), required=True)
        item.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
        item.add_argument("--sample-interval", type=int, default=60)
        item.add_argument("--judge-interval", type=int, default=24 * 60 * 60)
        item.add_argument("--port", type=int, default=39109)
        item.add_argument("--test-mode", action="store_true")
        item.add_argument("--duration-seconds", type=int)
    item = sub.add_parser("status")
    item.add_argument("--phase", choices=("soak", "pilot"), required=True)
    item.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "freeze":
        freeze()
        return 0
    if args.command == "status":
        status(args)
        return 0
    if args.test_mode and not args.duration_seconds:
        raise RuntimeError("--test-mode requires --duration-seconds")
    if args.command == "start":
        start_detached(args)
        return 0
    return run_phase(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"pilot runner failed: {error}", file=sys.stderr)
        raise SystemExit(1)
