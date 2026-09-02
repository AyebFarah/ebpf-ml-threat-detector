# Feature Engineering — v1

## 1. Versioning

Every row in `feature_windows` carries `feature_version` (definitions/formulas)
and `aggregation_version` (windowing strategy). Current values:

- `feature_version = "v1"`
- `aggregation_version = "sliding_15s_5s_v1"` (15s window, 5s stride)

Bump `feature_version` when a feature's *definition* changes (e.g. process
tree depth becomes globally computed instead of network-contextualized).
Bump `aggregation_version` when windowing itself changes (size, stride,
tumbling vs sliding). Rows from different versions can coexist in the same
table and must not be silently mixed in a single training run, filter by
version explicitly at export time.

## 2. Modularity

Each feature group is implemented as an independent function in
`observation/features/groups.py`, taking only the rows/context it needs:
`basic_counts`, `network_topology`, `traffic_volume`, `flow_dynamics`,
`rate_and_burstiness`, `dns_features`, `tls_features`, `http_features`,
`process_features`, `privilege_and_file_features`, `ssh_features`.
`extractor.py` is a thin orchestrator that calls each and merges results.
Changing one group's logic (e.g. DNS tunneling thresholds) never requires
touching the others.

## 3. Known Limitations, By Feature Group

### `process_tree_depth_max`

**Definition:** maximum ancestry depth observed among process executions
that appear in `process_observations` for this run, computed by walking
`exec_id -> parent_exec_id` in memory (`observation/features/process_tree.py`).

**Source:** `process_observations` joined to `correlated_events` for the run.

**Limitation:** depth is only as complete as captured process data.
Processes that started before the run (no `process_exec` event captured)
have no row, truncating the walk at that point rather than reaching a true
root. Only processes attached to at least one network connection in this
run are included at all, a process with no correlated connection never
enters the ancestry map.

**Planned improvement (v2):** a dedicated `process_tree` table populated at
ingestion time from all `process_exec` events (not just network-correlated
ones), or a precomputed `depth` column added directly to `process_observations`.

### `process_exec_count`, `unique_binary_count`

**Definition:** `process_exec_count` = count of distinct `exec_id` values
among `process_observations` rows for correlated events in this window.
`unique_binary_count` = count of distinct `process_name` values among the
same rows.

**Source:** `correlated_events` joined to `process_observations`.

**Limitation:** these are **network-contextualized** counts, not a full
system process census, "number of network-active process executions
observed in this window," not "total processes executed." A process that
never made a network connection is invisible to this feature. Still useful:
a scanning process shows up as many correlated events sharing one `exec_id`,
a host doing varied work shows more distinct binaries.

**Planned improvement (v2):** join against a standalone process-lifecycle
table independent of network correlation, once one exists.

### `seconds_since_last_privilege_event`, `seconds_since_last_sensitive_file_access`, `network_events_after_privilege_event`, `network_events_after_sensitive_file_access`

**Definition:** computed only from privilege/file activity events that are
already attached to a `correlated_event` in this run, i.e. events that fell
within the ±30s bidirectional correlation window used by `correlator.py`.

**Source:** `file_activity_events` / `privilege_activity_events`, joined via
`correlated_event_id`.

**Limitation:** does not see privilege or file activity that occurred
without any network connection nearby, a `sudo` invocation with no
network activity in the surrounding ±30s is invisible to these features,
by construction of the upstream correlator, not a bug in the aggregator.
These features capture "network activity that happens close to observed
privilege activity," not a global privilege timeline.

**Planned improvement (v2):** a standalone privilege/file event stream
independent of network correlation, with a configurable, possibly wider
lookback window.

### `base32_like_ratio`, `base64_like_ratio`, `hex_like_ratio`, `domain_label_entropy_mean`

**Definition:** for each DNS query's first (leftmost/subdomain) label,
test membership against a character-set rule:
- base32-like: label length ≥ 8, characters entirely from `[A-Z2-7]` (case-insensitive)
- base64-like: label length ≥ 8, characters entirely from `[A-Za-z0-9+/=]`
- hex-like: label length ≥ 8, characters entirely from `[0-9a-fA-F]`

Ratio = matching labels / total labels in the window. Implementation:
`observation/features/string_features.py`.

**Source:** `dns_observations.query_name`.

**Limitation:** these are heuristic character-set rules, not a tunneling
classifier. A short base64-looking label from ordinary CDN/tracking
subdomains will register as a "hit", this is expected noise at v1.
Thresholds (minimum length, exact alphabet) were chosen reasonably but not
yet tuned against real tunneling traffic, since none has been collected yet.

**Planned improvement (v2):** tune thresholds and add a proper entropy-based
or n-gram-based classifier once labeled DNS-tunneling attack data exists.

### `rare_ja4_ratio`

**Definition:** fraction of JA4 fingerprints in the window that appear fewer
than `RARE_JA4_THRESHOLD` (currently 3) times in the benign-baseline
frequency table, built once per feature-build run from all `label='benign'`
runs (`observation/features/baseline.py`).

**Limitation:** the baseline is only as broad as the benign corpus collected
so far, a legitimate but infrequently-visited service can register as
"rare" purely from under-sampling, not from being suspicious. Expect false
positives here to shrink as more benign runs and scenario variety accumulate.

## 4. Label Convention

`observation_runs.label` uses the format:
- `benign`
- `attack:<family>` (e.g. `attack:ssh_bruteforce`)
- `attack:<family>:<technique>` (e.g. `attack:ssh_bruteforce:T1110.001`)

Parsed at feature-build time (`extractor.parse_label`) into `feature_windows.label`
(0/1), `attack_family`, `attack_technique`. This convention must be used
consistently from the first attack-scenario run, retrofitting parsed labels
onto inconsistently-formatted `label` strings later is avoidable extra work.