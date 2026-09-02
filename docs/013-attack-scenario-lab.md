# Attack Scenario Lab — Design and Procedure

## 1. Goals

The attack lab is designed to:

1. **Generate labeled attack data** with precise timing and rich metadata for ML training and evaluation.
2. **Ensure tight run bracketing** so that each run’s label (`attack:<family>:<technique>` or `benign`) cleanly applies to the captured telemetry.
3. **Provide reproducible, parameterized scenarios** (SSH brute force, port scan, DNS tunneling, C2 beacon, data exfiltration) with configurable intensity.
4. **Include near-miss (benign but attack-like) scenarios** to evaluate false-positive behavior and avoid oversimplified “attack = bad pattern” learning.
5. **Enforce safety and isolation**, ensuring attacks only target designated lab subnets and never production or external systems.
6. **Integrate cleanly with the existing observation pipeline**, reusing the same normalization, correlation, and database layers used for benign data.

---

## 2. Design principles

### 2.1. Tight run bracketing

A key risk in attack-data collection is **label leakage**: if a run contains long benign periods before/after a short attack, but the entire run is labeled `attack:...`, then the model learns from mislabeled data.

To avoid this, we enforce:

- The observation pipeline starts **just before** the attack script runs.
- The attack script runs for a **short, well-defined duration** (seconds to a few minutes).
- The pipeline stops **shortly after** the attack ends.
- Only a few seconds of padding are allowed on each side.

This is implemented in `run_attack_scenario.py`:

```text
start pipeline
  → wait for collectors to be ready
  → record attack_start_ts
  → run attack script
  → record attack_end_ts
  → short settle delay
  → stop pipeline + post-process
```

The resulting `run_id` covers mostly attack traffic, with minimal benign padding.

### 2.2. Rich, structured metadata

For every attack run, we record:

- **Identity**: `run_id`, `scenario`, `label`.
- **Attack semantics**: `attack_family`, `attack_technique` (MITRE ATT&CK ID).
- **Operational details**: `tool`, `tool_version`, `target_host`, `target_port`, `intensity`.
- **Timing**: `attack_start_ts`, `attack_end_ts`, `duration_seconds`.
- **Expectations**: `expected_behavior` (short description of what the telemetry should look like).
- **Provenance**: `operator`, `notes`, full attack command line.

This is stored in two places:

1. **SQLite**: `attack_run_metadata` table, linked to `observation_runs.run_id`.
2. **JSON manifest**: `observation/attack_lab/runs/<timestamp>_<scenario>_run<run_id>.json`.

This dual storage makes the data both queryable (SQL) and portable/self-describing (JSON).

### 2.3. MITRE ATT&CK alignment

Attack labels follow a strict format:

```text
attack:<family>:<technique>
```

where:

- `<family>` is a lowercase, underscore-separated name (e.g. `ssh_bruteforce`, `port_scan`).
- `<technique>` is a MITRE ATT&CK technique ID (e.g. `T1110.001`, `T1046`, `T1071.004`).

Examples:

- `attack:ssh_bruteforce:T1110.001` : Brute Force: SSH.
- `attack:port_scan:T1046` : Network Service Discovery.
- `attack:dns_tunneling:T1071.004` : Application Layer Protocol: DNS.
- `attack:c2_beacon:T1071.001` : Application Layer Protocol: Web Protocols.
- `attack:exfiltration:T1041` : Exfiltration Over C2 Channel.

This design:

- Makes labels **machine-checkable** via regex.
- Enables future mapping to threat-intel frameworks and public detections.
- Encourages consistent naming across scenarios.

Label validation is enforced in `observation/attack_lab/label_validator.py`.

### 2.4. Near-miss scenarios

To avoid training a model that simply learns “any scan = malicious” or “many DNS queries = tunneling”, we include **near-miss** scenarios:

- `admin_nmap_inventory.sh`: legitimate admin network inventory (ping sweep + light port scan).
- `ssh_retry_storm.sh`: misconfigured backup script retrying SSH with a stale password.
- `dev_dns_burst.sh`: dev/deploy script performing rapid DNS lookups for service discovery.

These are:

- Labeled as `benign`.
- Placed in `observation/attack_lab/near_miss/` to distinguish them from attack scripts.
- Documented with `notes` indicating they are near-miss.

This allows us to:

- Measure false-positive rates on realistic benign activity.
- Train models that distinguish **intent** and **context**, not just raw patterns.

### 2.5. Safety & isolation

The lab is designed for **isolated virtual environments** (e.g. QEMU/KVM with an isolated `attack-lab` network). Key safety properties:

- **Allowed subnets**: `config.py` defines `ALLOWED_TARGET_SUBNETS` (e.g. `192.168.56.0/24`, `192.168.100.0/24`).
- **Enforced in code**: `run_attack_scenario.py` validates `--target` against this list and refuses to run if the target is outside allowed subnets.
- **Script-level awareness**: each attack script includes comments reminding the operator of safe usage.

This ensures that even if the operator makes a mistake, the wrapper prevents obvious misuse.

---

## 3. Implementation overview

### 3.1. Folder structure

```text
observation/attack_lab/
├── config.py                 # Allowed subnets, intensity profiles, constants
├── label_validator.py        # Validates attack labels
├── pipeline_controller.py    # Starts/stops the observation pipeline for scripted runs
├── run_attack_scenario.py    # Main wrapper: start → attack → stop → metadata
├── runs/                     # JSON manifests per attack run (git-ignored)
├── scenarios/                # Attack scripts
│   ├── ssh_bruteforce.sh
│   ├── port_scan.sh
│   ├── dns_tunneling.sh
│   ├── c2_beacon.sh
│   └── data_exfiltration.sh
└── near_miss/                # Benign but attack-like scenarios
    ├── ssh_retry_storm.sh
    ├── admin_nmap_inventory.sh
    └── dev_dns_burst.sh
```

### 3.2. Core components

#### `label_validator.py`

Validates labels:

- `benign` is always allowed.
- Attack labels must match `^attack:[a-z0-9_]+:T\d{4}(\.\d{3})?$`.

This prevents accidental typos or inconsistent formats.

#### `config.py`

Defines:

- `ALLOWED_TARGET_SUBNETS`: list of CIDR ranges considered safe.
- Helper `is_target_allowed(host)` to check if a target IP is in an allowed subnet.
- Intensity profiles (`low`, `medium`, `high`) and their descriptions.

#### `pipeline_controller.py`

A thin wrapper around the observation pipeline:

- `start()`: creates directories, resets logs, verifies dependencies, starts all collectors.
- `wait_ready()`: sleeps for a configured warmup period (e.g. 5s).
- `stop_and_postprocess(...)`: stops all collectors, runs normalization → correlation → DB load, returns `run_id`.

This isolates the “pipeline lifecycle” logic from the attack-runner.

#### `run_attack_scenario.py`

Main wrapper script. Flow:

1. Parse CLI arguments (`--scenario`, `--family`, `--technique`, `--target`, `--intensity`, etc.).
2. Validate label format via `label_validator.validate_label()`.
3. Validate target IP against `ALLOWED_TARGET_SUBNETS`.
4. Start the pipeline via `AttackPipelineController`.
5. Wait for collectors to be ready.
6. Record `attack_start_ts`, run the attack script as a subprocess, record `attack_end_ts`.
7. Short settle delay (e.g. 5s).
8. Stop the pipeline and run post-processing, obtaining `run_id`.
9. Insert a row into `attack_run_metadata` with all metadata.
10. Write a JSON manifest to `runs/`.
11. Update the DB row with the manifest path.

This ensures every attack run is:

- Tightly bracketed.
- Fully metadata-rich.
- Traceable back to the exact command and parameters.

#### Attack scripts (`scenarios/`, `near_miss/`)

Each script:

- Takes parameters (target, intensity, etc.).
- Prints a header with scenario name, parameters, and `start_ts`.
- Executes the attack (or benign near-miss behavior).
- Prints `end_ts` and a footer.

They are simple, self-contained, and designed to be invoked from the wrapper.

---

## 4. Data model

### 4.1. `observation_runs`

Standard run metadata:

- `run_id`: primary key.
- `started_at`, `ended_at`, `status`.
- `scenario`: e.g. `ssh_bruteforce`, `admin_nmap_inventory`.
- `label`: `benign` or `attack:<family>:<technique>`.
- `notes`, `duration_seconds`.

### 4.2. `attack_run_metadata`

Additional attack-specific fields in `observation/database/migrations/004-attack_run_metadata.sql`

The added table:

- Links each attack run to its MITRE technique, tool, target, and timing.
- Enables queries like “all SSH brute force runs” or “all runs with intensity=high”.

### 4.3. JSON manifests

Each manifest in `runs/` contains:

- All fields from `attack_run_metadata`.
- The exact attack command line.
- Schema/version info for future evolution.

Example:

```json
{
  "manifest_version": "v1",
  "schema": "attack-run-manifest-v1",
  "run_id": 42,
  "scenario": "ssh_bruteforce",
  "label": "attack:ssh_bruteforce:T1110.001",
  "attack_command": ["./scenarios/ssh_bruteforce.sh", "192.168.56.10", "testuser", "medium"],
  "parameters": {
    "raw_command": ["./scenarios/ssh_bruteforce.sh", "192.168.56.10", "testuser", "medium"]
  },
  "attack_start_ts": "2026-08-31T11:00:05+02:00",
  "attack_end_ts": "2026-08-31T11:00:35+02:00",
  "duration_seconds": 30,
  "tool": "hydra",
  "tool_version": "0.9.1",
  "target_host": "192.168.56.10",
  "target_port": 22,
  "intensity": "medium",
  "expected_behavior": "Many SSH auth failures from one source IP to one target",
  "notes": "Lab VM, isolated network",
  "operator": "Username"
}
```

---

## 5. Attack scenarios

### 5.1. Malicious scenarios (`scenarios/`)

- **`ssh_bruteforce.sh`**  
  Simulates SSH password brute-forcing using `hydra`.  
  Parameters: `<victim_ip> <username> <low|medium|high>`.

- **`port_scan.sh`**  
  Simulates TCP port scanning using `nmap`.  
  Parameters: `<victim_ip> <low|medium|high>`.

- **`dns_tunneling.sh`**  
  Simulates DNS tunneling by sending random subdomain queries.  
  Parameters: `<domain> <low|medium|high>`.

- **`c2_beacon.sh`**  
  Simulates periodic C2 beaconing over raw TCP.  
  Parameters: `<attacker_ip> <low|medium|high>`.

- **`data_exfiltration.sh`**  
  Simulates bulk data exfiltration over TCP.  
  Parameters: `<attacker_ip> <low|medium|high>`.

Each supports three intensity levels (`low`, `medium`, `high`) with different:

- Thread counts / rates.
- Durations / number of requests.
- Resource footprint.

### 5.2. Near-miss scenarios (`near_miss/`)

- **`admin_nmap_inventory.sh`**  
  Legitimate admin network inventory (ping sweep + light port scan).

- **`ssh_retry_storm.sh`**  
  Misconfigured script retrying SSH with a stale password.

- **`dev_dns_burst.sh`**  
  Dev/deploy script performing rapid DNS lookups for service discovery.

These are labeled as `benign` but intentionally resemble attack patterns.

---

## 6. Usage pattern

### 6.1. Typical attack run

```bash
python3 -m observation.attack_lab.run_attack_scenario \
  --scenario ssh_bruteforce \
  --family ssh_bruteforce \
  --technique T1110.001 \
  --tool hydra \
  --intensity medium \
  --target 192.168.56.10 \
  --target-port 22 \
  --expected "Many SSH auth failures from one source IP to one target" \
  --notes "Lab VM, isolated network" \
  --operator pharah \
  -- ./observation/attack_lab/scenarios/ssh_bruteforce.sh 192.168.56.10 testuser medium
```

Result:

- One `observation_runs` row with `label = 'attack:ssh_bruteforce:T1110.001'`.
- One `attack_run_metadata` row with full details.
- One JSON manifest in `runs/`.
- All correlated events for that `run_id` in the main DB.

### 6.2. Near-miss run

Same command, but:

- Script from `near_miss/`.
- `--family` and `--technique` can still be MITRE-like (for documentation), but label in DB is `benign`.
- `notes` indicate “Near-miss: legitimate admin activity”.

---

## 7. Evaluation strategy

When evaluating models:

- Use `attack_run_metadata` to:
  - Filter by `attack_family`, `scenario`, `intensity`.
  - Separate development vs test runs.
- Use near-miss runs to:
  - Measure false-positive rates.
  - Ensure the model doesn’t overfit to superficial patterns.

The tight bracketing ensures that:

- Attack runs are mostly attack traffic.
- Benign runs are mostly benign traffic.
- Labels are trustworthy for training and evaluation.

---

## 8. Extending the lab

### 8.1. Adding a new attack scenario

1. Create a new script in `scenarios/` with:
  - Parameter parsing (target, intensity).
  - Clear header/footer with timestamps.
  - Attack logic.
2. Make it executable.
3. Run it via the wrapper with appropriate `--scenario`, `--family`, `--technique`.

### 8.2. Adding a new near-miss scenario

Same process, but place the script in `near_miss/` and label the run as `benign`.

