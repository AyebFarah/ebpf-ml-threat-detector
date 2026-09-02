#!/usr/bin/env python3
"""
Wrapper for attack-scenario collection runs. Handles:
  - starting the observation pipeline
  - waiting for collectors to be ready
  - running the attack script with precise start/end timestamps
  - stopping the pipeline (triggers post-processing: normalize/correlate/load)
  - writing a JSON manifest to observation/samples/attack_runs/
  - inserting the attack_run_metadata row

Usage:
  python3 -m observation.attack_lab.run_attack_scenario \
      --scenario ssh_bruteforce \
      --technique T1110.001 \
      --family ssh_bruteforce \
      --tool hydra \
      --intensity medium \
      --target 192.168.56.10 \
      --target-port 22 \
      --expected "Many SSH auth failures from one source IP to one target" \
      --notes "Lab VM, isolated network" \
      --operator Username \
      -- ./observation/attack_lab/ssh_bruteforce.sh 192.168.56.10 testuser medium
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone

from .pipeline_controller import AttackPipelineController
from . import config
from .config import is_target_allowed
from .label_validator import validate_label
from .. import paths
from ..database.connection import connect, apply_migrations
from ..database.repositories.attack_run_metadata import AttackRunMetadataRepository

COLLECTOR_WARMUP_SECONDS = 5
SETTLE_SECONDS = 5


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def _tool_version(tool: str) -> str | None:
    if not tool:
        return None
    for flag in ("--version", "-V", "-v"):
        try:
            out = subprocess.run([tool, flag], capture_output=True, text=True, timeout=5)
            text = (out.stdout + out.stderr).strip().splitlines()
            if text:
                return text[0][:200]
        except Exception:
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description="Run a bracketed attack-scenario collection")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--technique", required=True, help="MITRE technique ID, e.g. T1110.001")
    parser.add_argument("--tool")
    parser.add_argument("--intensity", choices=["low", "medium", "high"])
    parser.add_argument("--target")
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--notes")
    parser.add_argument("--operator", required=True)
    parser.add_argument("attack_cmd", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if not args.attack_cmd or args.attack_cmd[0] != "--":
        parser.error("attack command must be given after a literal '--'")
    attack_cmd = args.attack_cmd[1:]
    if not attack_cmd:
        parser.error("no attack command given after '--'")

    label = f"attack:{args.family}:{args.technique}"
    validate_label(label)

    # Safety gate: refuse to run against anything outside the lab subnets,
    # before the pipeline is even started. Scenarios with no meaningful
    # single target (e.g. dns_tunneling, credential_access run locally)
    # can omit --target; anything that does pass --target must be inside
    # ALLOWED_TARGET_SUBNETS.
    if args.target and not is_target_allowed(args.target):
        parser.error(
            f"Target {args.target!r} is not in an allowed lab subnet. "
            f"Allowed: {config.ALLOWED_TARGET_SUBNETS}"
        )

    print(f"[wrapper] scenario={args.scenario} label={label}")
    print(f"[wrapper] attack command: {' '.join(attack_cmd)}")

    controller = AttackPipelineController(warmup_seconds=COLLECTOR_WARMUP_SECONDS)
    controller.start()
    controller.wait_ready()

    attack_start_ts = _now_iso()
    print(f"[wrapper] attack starting at {attack_start_ts}")
    result = subprocess.run(attack_cmd)
    attack_end_ts = _now_iso()
    print(f"[wrapper] attack finished at {attack_end_ts} (exit code {result.returncode})")

    time.sleep(SETTLE_SECONDS)  # let trailing packets/events land before stopping capture

    duration_seconds = int(
        (datetime.fromisoformat(attack_end_ts) - datetime.fromisoformat(attack_start_ts)).total_seconds()
    )
    run_id = controller.stop_and_postprocess(
        scenario=args.scenario, label=label, notes=args.notes,
        duration_seconds=duration_seconds,
    )

    tool_version = _tool_version(args.tool) if args.tool else None
    parameters = {"raw_command": attack_cmd}

    apply_migrations()
    with connect() as conn:
        AttackRunMetadataRepository(conn).insert(
            run_id=run_id, attack_family=args.family, attack_technique=args.technique,
            scenario=args.scenario, tool=args.tool, tool_version=tool_version,
            target_host=args.target, target_port=args.target_port,
            intensity=args.intensity, parameters=parameters,
            attack_start_ts=attack_start_ts, attack_end_ts=attack_end_ts,
            expected_behavior=args.expected, notes=args.notes, operator=args.operator,
            manifest_path=None,
        )

    paths.ATTACK_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    ts_slug = attack_start_ts.replace(":", "-").split("+")[0].split(".")[0]
    manifest_path = paths.ATTACK_RUNS_DIR / f"{ts_slug}_{args.scenario}_run{run_id}.json"
    manifest = {
        "run_id": run_id, "scenario": args.scenario, "label": label,
        "attack_command": attack_cmd, "parameters": parameters,
        "attack_start_ts": attack_start_ts, "attack_end_ts": attack_end_ts,
        "duration_seconds": duration_seconds, "tool": args.tool,
        "tool_version": tool_version, "target_host": args.target,
        "target_port": args.target_port, "intensity": args.intensity,
        "expected_behavior": args.expected, "notes": args.notes,
        "operator": args.operator,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[wrapper] manifest written -> {manifest_path}")

    with connect() as conn:
        conn.execute(
            "UPDATE attack_run_metadata SET manifest_path = ? WHERE run_id = ?",
            (str(manifest_path), run_id),
        )

    print(f"[wrapper] run_id={run_id} complete. "
          f"Run 'python3 -m observation.database.reports.run_summary {run_id}'")


if __name__ == "__main__":
    sys.exit(main())