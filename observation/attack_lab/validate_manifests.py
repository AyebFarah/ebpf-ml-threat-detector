"""
Cross-checks every manifest in observation/samples/attack_runs/ against
the database row it claims to describe. A manifest is valid only when
run_id, scenario, and attack_start_ts all agree with the database, and
its own content hash still matches manifest_hash (catches hand-edited
or corrupted files). A run_id existing in the database is not enough:
after a run_id is reused, an old manifest can name a real run_id that
now belongs to a completely different run.

Usage: python3 -m observation.attack_lab.validate_manifests
"""
import glob
import json
import hashlib
from observation import paths
from observation.database.connection import connect
from observation.database.models import ObservationRun, AttackRunMetadata
from sqlalchemy import select


def _manifest_hash(manifest: dict) -> str:
    m = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    return hashlib.sha256(json.dumps(m, sort_keys=True, default=str).encode()).hexdigest()


def validate_all():
    problems = []
    with connect() as conn:
        for path in sorted(glob.glob(str(paths.ATTACK_RUNS_DIR / "*.json"))):
            try:
                manifest = json.loads(open(path).read())
            except (json.JSONDecodeError, OSError) as exc:
                problems.append((path, f"unreadable: {exc}"))
                continue

            run_id = manifest.get("run_id")
            row = conn.execute(select(
                ObservationRun.scenario, ObservationRun.started_at
            ).where(ObservationRun.run_id == run_id)).mappings().first()

            if row is None:
                problems.append((path, f"run_id={run_id} no longer exists in the database"))
                continue
            if row["scenario"] != manifest.get("scenario"):
                problems.append((path, f"scenario mismatch: manifest={manifest.get('scenario')!r} "
                                       f"db={row['scenario']!r} (run_id likely reused)"))
                continue

            meta = conn.execute(select(AttackRunMetadata.run_uuid, AttackRunMetadata.manifest_hash)
                                .where(AttackRunMetadata.run_id == run_id)).mappings().first()
            if meta is None:
                problems.append((path, f"run_id={run_id} has no attack_run_metadata row"))
                continue
            if meta["run_uuid"] != manifest.get("run_uuid"):
                problems.append((path, "run_uuid mismatch (run_id reused since this manifest was written)"))
                continue
            if "manifest_hash" in manifest and _manifest_hash(manifest) != manifest["manifest_hash"]:
                problems.append((path, "manifest_hash mismatch: file was edited after being written"))

    if problems:
        print(f"[validate] {len(problems)} problem manifest(s):")
        for path, reason in problems:
            print(f"  {path}: {reason}")
    else:
        print("[validate] all manifests match their database rows")
    return problems


if __name__ == "__main__":
    import sys
    sys.exit(1 if validate_all() else 0)