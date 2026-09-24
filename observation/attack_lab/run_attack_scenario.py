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
import hashlib
import uuid
from datetime import datetime, timezone
from sqlalchemy import update
from observation.attack_lab.pipeline_controller import AttackPipelineController
from observation.attack_lab import config
from observation.attack_lab.config import is_target_allowed
from observation.attack_lab.label_validator import validate_label
from observation import paths
from observation.database.connection import connect, apply_migrations
from observation.database.repositories.attack_run_metadata import AttackRunMetadataRepository
from observation.database.repositories.runs import RunsRepository
from observation.database.models import AttackRunMetadata


COLLECTOR_WARMUP_SECONDS = 5
SETTLE_SECONDS = 10


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def _tool_version(tool: str) -> str | None:
    if not tool:
        return None
    for flag in ("--version", "-V", "-v"):
        try:
            out = subprocess.run([tool, flag], capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        if out.returncode != 0:   # dig --version exits 1 with "Invalid option": not a version
            continue
        text = (out.stdout + out.stderr).strip().splitlines()
        if text:
            return text[0][:200]
    return None

def _manifest_hash(manifest: dict) -> str:
    m = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    blob = json.dumps(m, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def _write_manifest_and_retire_stale(manifest_path, manifest, run_id, scenario):
    """A run_id can be reused after the row it named was deleted (this
    project has already hit that case). Any earlier manifest file that
    claims this run_id but does not match the current database row is
    stale and must not be left lying around looking valid, so it is
    renamed with a .stale suffix rather than silently overwritten or
    silently ignored."""
    for old in paths.ATTACK_RUNS_DIR.glob("*.json"):
        try:
            old_data = json.loads(old.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if old_data.get("run_id") == run_id and old_data.get("run_uuid") != manifest["run_uuid"]:
            print(f"[wrapper] retiring stale manifest for reused run_id={run_id}: {old.name}")
            old.rename(old.with_suffix(".json.stale"))
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[wrapper] manifest written -> {manifest_path}")

FLAGS_WITH_VALUE = {"-i", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-m",
                    "-S", "-E", "-e", "-W", "-w", "-B", "-I", "-Q", "-O"}


def _control_channel(attack_cmd):
    """If the attack command is 'ssh [options] [user@]host cmd', the wrapper's own SSH
    connection to that host is harness traffic, not attack traffic. Returns its endpoint."""
    if not attack_cmd or attack_cmd[0] != "ssh":
        return None
    args, i, port = attack_cmd[1:], 0, 22
    while i < len(args):
        a = args[i]
        if a == "-p" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2; continue
        if a in FLAGS_WITH_VALUE:
            i += 2; continue
        if a.startswith("-"):
            i += 1; continue
        return {"host": a.split("@", 1)[-1], "port": port}
    return None


def main():
    parser = argparse.ArgumentParser(description="Run a bracketed attack-scenario collection")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--technique", required=True, help="MITRE technique ID, e.g. T1110.001")
    parser.add_argument("--tool")
    parser.add_argument("--tool-version", help="Version of the tool as installed on the machine that runs it")
    parser.add_argument("--intensity", choices=["low", "medium", "high"])
    parser.add_argument("--repetitions", type=int, default=1, help="Number of times to run the attack command within this single bracketed observation window (default 1)")
    parser.add_argument("--pause-seconds", type=float, default=0, help="Seconds to sleep between repetitions (default 0)")
    parser.add_argument("--target")
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--notes")
    parser.add_argument("--operator", required=True)
    parser.add_argument("attack_cmd", nargs=argparse.REMAINDER)
    parser.add_argument("--allow-nonzero-exit", action="store_true",
                        help="Keep a run whose attack command exited nonzero, marked "
                             "quality=partial with a recorded failure_reason, instead "
                             "of marking the run failed. Use only for an intentionally "
                             "negative test, not to paper over a broken scenario.")
    parser.add_argument("--failure-reason", help="Required with --allow-nonzero-exit: why a nonzero exit is expected/acceptable for this run.")
    args = parser.parse_args()
    if args.allow_nonzero_exit and not args.failure_reason:
        parser.error("--allow-nonzero-exit requires --failure-reason")

    if args.repetitions < 1:
        parser.error("--repetitions must be >= 1")

    if args.pause_seconds < 0:
        parser.error("--pause-seconds must be >= 0")

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

    run_id = None
    interrupted = False
    exit_codes = []
    try:
        attack_start_ts = _now_iso()
        print(f"[wrapper] attack starting at {attack_start_ts} "
              f"({args.repetitions} repetition(s), pause={args.pause_seconds}s)")

        for rep in range(1, args.repetitions + 1):
            print(f"[wrapper] --- repetition {rep}/{args.repetitions} ---")
            result = subprocess.run(attack_cmd)
            exit_codes.append(result.returncode)
            print(f"[wrapper] repetition {rep} finished (exit code {result.returncode})")
            if rep < args.repetitions and args.pause_seconds > 0:
                time.sleep(args.pause_seconds)

        attack_end_ts = _now_iso()
        print(f"[wrapper] all {args.repetitions} repetition(s) finished at {attack_end_ts} "
              f"(exit codes: {exit_codes})")
        time.sleep(SETTLE_SECONDS)

        duration_delta = datetime.fromisoformat(attack_end_ts) - datetime.fromisoformat(attack_start_ts)
        duration_ms = int(duration_delta.total_seconds() * 1000)

        run_id = controller.stop_and_postprocess(
            scenario=args.scenario, label=label, notes=args.notes, duration_ms=duration_ms,
        )
    except KeyboardInterrupt:
        interrupted = True
        print("[wrapper] interrupted by operator")
    finally:
        if run_id is None and controller.supervisor is not None:
            print("[wrapper] attack run did not complete normally, stopping collectors")
            controller.supervisor.stop_all()

    if run_id is None:
        # Nothing reached post-processing: this attempt produced no telemetry at all,
        # so there is no observation_runs row to mark. Nothing further to do.
        sys.exit(130 if interrupted else 1)

    failed_reps = [i + 1 for i, code in enumerate(exit_codes) if code != 0]
    is_failure = bool(failed_reps) and not args.allow_nonzero_exit

    apply_migrations()

    if interrupted:
        with connect() as conn:
            RunsRepository(conn).set_quality(run_id, "interrupted", "operator interrupted the run")
        print(f"[wrapper] run_id={run_id} marked interrupted, no attack_run_metadata written")
        sys.exit(130)

    if is_failure:
        with connect() as conn:
            RunsRepository(conn).fail_run(run_id, f"attack command failed in repetitions {failed_reps}")
            RunsRepository(conn).set_quality(run_id, "failed", f"exit codes {exit_codes}")
        print(f"[wrapper] run_id={run_id} marked failed (repetitions {failed_reps} exited nonzero), "
              f"excluded from feature building")
        sys.exit(2)

    # Reaching here means either every repetition exited 0, or the operator explicitly
    # accepted nonzero exits via --allow-nonzero-exit with a recorded reason.
    quality = "full"
    if failed_reps:  # allow_nonzero_exit was set
        quality = "partial"
        print(f"[wrapper] WARNING: repetitions {failed_reps} exited nonzero but "
              f"--allow-nonzero-exit was set; run_id={run_id} kept as quality=partial")
    try:
        tool_version = args.tool_version or (_tool_version(args.tool) if args.tool else None)
        run_uuid = str(uuid.uuid4())
        parameters = {
            "raw_command": attack_cmd, "repetitions": args.repetitions,
            "pause_seconds": args.pause_seconds, "exit_codes": exit_codes,
            "allow_nonzero_exit": args.allow_nonzero_exit,
            "quality": quality,
            "failure_reason": args.failure_reason if args.allow_nonzero_exit else None,
            "control_channel": _control_channel(attack_cmd),
        }

        manifest = {
            "manifest_version": "v2",
            "run_uuid": run_uuid,
            "run_id": run_id, "scenario": args.scenario, "label": label,
            "attack_command": attack_cmd, "parameters": parameters,
            "attack_start_ts": attack_start_ts, "attack_end_ts": attack_end_ts,
            "duration_ms": duration_ms, "repetitions": args.repetitions,
            "pause_seconds": args.pause_seconds, "tool": args.tool,
            "tool_version": tool_version, "target_host": args.target,
            "target_port": args.target_port, "intensity": args.intensity,
            "expected_behavior": args.expected, "notes": args.notes,
            "operator": args.operator, "created_at": _now_iso(),
        }
        manifest["manifest_hash"] = _manifest_hash(manifest)

        with connect() as conn:
            AttackRunMetadataRepository(conn).insert(
                run_id=run_id, attack_family=args.family, attack_technique=args.technique,
                scenario=args.scenario, tool=args.tool, tool_version=tool_version,
                target_host=args.target, target_port=args.target_port,
                intensity=args.intensity, parameters=parameters,
                attack_start_ts=attack_start_ts, attack_end_ts=attack_end_ts,
                expected_behavior=args.expected, notes=args.notes, operator=args.operator,
                manifest_path=None, run_uuid=run_uuid, manifest_hash=manifest["manifest_hash"],
                allow_nonzero_exit=args.allow_nonzero_exit,
            )
            RunsRepository(conn).mark_completed(run_id)
            RunsRepository(conn).set_quality(run_id, quality, args.failure_reason if args.allow_nonzero_exit else None)

        paths.ATTACK_RUNS_DIR.mkdir(parents=True, exist_ok=True)
        ts_slug = attack_start_ts.replace(":", "-").split("+")[0].split(".")[0]
        manifest_path = paths.ATTACK_RUNS_DIR / f"{ts_slug}_{args.scenario}_run{run_id}_{run_uuid[:8]}.json"
        _write_manifest_and_retire_stale(manifest_path, manifest, run_id, args.scenario)

        with connect() as conn:
            conn.execute(update(AttackRunMetadata).where(
                AttackRunMetadata.run_id == run_id
            ).values(manifest_path=str(manifest_path)))

        print(f"[wrapper] run_id={run_id} run_uuid={run_uuid} status=complete, quality={quality}. "
              f"Run 'python3 -m observation.database.reports.run_summary {run_id}'")
    except Exception as exc:
        with connect() as conn:
            RunsRepository(conn).fail_run(run_id, f"wrapper error after load: {exc!r}")
        raise
    return 0 if quality != "partial" else 3


if __name__ == "__main__":
    sys.exit(main())
