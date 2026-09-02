# Feature Pipeline

## 1. Inputs

| Table | Role |
|---|---|
| `observation_runs` | source of `run_id`, `scenario`, `label` (parsed into 0/1 + attack_family/technique) |
| `correlated_events` | primary event stream, one row per `tcp_connect` |
| `process_observations` | joined per correlated_event; also source for ancestry map (process tree depth) |
| `dns_observations`, `tls_observations`, `tcp_flow_observations`, `http_observations` | joined per correlated_event, one signal each |
| `file_activity_events`, `privilege_activity_events` | joined per correlated_event, list-valued |
| `ssh_sessions` | independent per-run entity, matched into windows by `earliest_event_ts` |

Only runs with `status = 'completed'` are processed by `--all`. Runs can be
explicitly excluded (`--exclude <run_id> ...`), used for runs under
suspicion of a correlation defect.

## 2. Outputs

- **`feature_windows`** (SQLite table) : the primary output. One row per
  `(run_id, window_start_ts, entity_type, entity_id)`.
- **JA4 baseline** : built in-memory each pipeline invocation from all
  `label='benign'` runs' `tls_observations.ja4` values
  (`observation/features/baseline.py`). Not currently persisted to disk,
  if reproducibility of a specific past `rare_ja4_ratio` value is ever
  needed, add a `--dump-baseline baseline.json` flag (not yet implemented).
- **Flat-file export** (CSV/Parquet) : not yet implemented, planned next
  step once `feature_windows` is validated, for handoff to the ML/training
  pipeline outside this repo's SQLite dependency.

## 3. Configuration

All in `observation/features/config.py`:

| Constant | Current value | Meaning |
|---|---|---|
| `FEATURE_VERSION` | `"v1"` | bump when a feature's definition changes |
| `AGGREGATION_VERSION` | `"sliding_15s_5s_v1"` | bump when windowing strategy changes |
| `WINDOW_SECONDS` | 15 | sliding window size |
| `STRIDE_SECONDS` | 5 | stride between window starts (overlap is intentional) |
| `WELL_KNOWN_PORT_MAX` | 1024 | boundary for `well_known_port_ratio` |
| `HIGH_PORT_MIN` | 49152 | boundary for `high_port_ratio` |
| `RARE_JA4_THRESHOLD` | 3 | JA4 count in benign baseline below which it's "rare" |
| `SENSITIVE_TIER1_PREFIXES` | see file | credential/persistence paths |
| `SHELL_BINARIES`, `INTERPRETER_BINARIES` | see file | basename sets for `shell_spawn_count`/`interpreter_spawn_count` |

Changing any of these and re-running against existing data does **not**
retroactively update `feature_version`/`aggregation_version` on old rows,
bump those constants manually in `config.py` when you change definitions,
so old and new rows remain distinguishable in the table.

## 4. Commands

Build/rebuild everything:
```bash
python3 -m observation.features.cli --all
```

Exclude specific runs (e.g. known-bad correlation):
```bash
python3 -m observation.features.cli --all --exclude 15
```

Rebuild specific runs only:
```bash
python3 -m observation.features.cli --run-id 7 --run-id 12
```

## 5. Idempotency and Re-run Safety

`FeatureWindowsRepository.upsert_for_run(run_id, windows)` wraps delete+insert
for a single run_id in one transaction: existing rows for that `run_id` are
deleted, then the freshly computed windows are inserted, committed together.
A failure mid-insert rolls back the delete too, a run's windows are never
left partially rebuilt or duplicated.

Console output on each run processed:
```text
[features] deleting existing windows for run_id=7 (2481 removed)
[features] inserting 2481 windows for run_id=7
```

This means re-running the CLI against the same run_id(s), after a config
change, a bugfix in `groups.py`, or a version bump, is always safe and
produces exactly the current definitions' output, never accumulating stale
duplicate windows from a prior run of the pipeline.

## 6. Typical Workflow After a New Collection Session

```bash
# 1. Confirm the new run is completed and sane
python3 -m observation.database.reports.run_summary <run_id>

# 2. Build features for just that run
python3 -m observation.features.cli --run-id <run_id>

# 3. Spot-check
sqlite3 observation/database/observations.db \
  "SELECT entity_type, COUNT(*) FROM feature_windows WHERE run_id=<run_id> GROUP BY entity_type;"
```

Full-corpus rebuilds (`--all`) are only needed after a `groups.py`/`config.py`
change that should apply retroactively to every run.