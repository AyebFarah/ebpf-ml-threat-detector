# Process Lifecycle Collector — Design and Implementation

## 1. Purpose

The process lifecycle collector attributes every observed action (network connection,
file access, privilege use) to the process that performed it, and captures that
process's lineage (parent, grandparent, executable path, arguments).

Without this, an enriched event says:

```text
192.168.1.10 → 185.XXX.XXX.XXX:443
```

With process context attached, it says:

```text
/usr/bin/python3 (pid 45678), launched by /usr/sbin/sshd,
executed "update.py --sync" from /home/pharah,
contacted 185.XXX.XXX.XXX:443
```

This is the foundation every later correlation (file activity, privilege activity, HTTP)
is anchored to.

## 2. Why No New TracingPolicy Was Needed

Unlike the TCP, DNS, SSH, and sensitive-file-access collectors, process lifecycle did not
require a new `TracingPolicy` YAML file. Tetragon emits `process_exec` and `process_exit`
as **core events** from its base sensor, they are not kprobe hooks attached via a
tracing policy, they are always present as long as `tetra getevents` is running.

This meant the only work required was:

1. Recognizing `process_exec` / `process_exit` payloads in the dispatcher (they have no
   `process_kprobe` key, so they needed their own routing branch).
2. Writing normalizers to convert them into the unified event schema.

## 3. Dispatcher Routing

`observation/pipeline/dispatcher.py` was extended to check for `process_exec` and
`process_exit` keys before falling through to the generic `process_kprobe` /
`policy_name` routing used by every other kprobe-based collector:

Output files:

```text
samples/event_logs_by_policy/process-exec.jsonl
samples/event_logs_by_policy/process-exit.jsonl
```

## 4. Collected Information

### `process_exec`

| Field | Source | Notes |
|---|---|---|
| `exec_id` | `process.exec_id` | Cluster/node-unique process execution identifier |
| `parent_exec_id` | `process.parent_exec_id` | Links to the parent's `process_exec` event |
| `pid` / `parent_pid` | `process.pid` / `parent.pid` | |
| `binary` / `parent_binary` | `process.binary` / `parent.binary` | Full executable path |
| `arguments` | `process.arguments` | Command-line arguments as invoked |
| `uid` / `auid` | `process.uid` / `process.auid` | Effective UID and audit (login) UID |
| `cwd` | `process.cwd` | Working directory at exec time |
| `start_time` | `process.start_time` | Kernel-observed start timestamp |

### `process_exit`

| Field | Source | Notes |
|---|---|---|
| `exec_id` | `process.exec_id` | Matches the corresponding `process_exec` |
| `signal` | top-level `signal` | Non-null if the process was killed by a signal |
| `status` | top-level `status` | Exit code |

## 5. Normalization

Two dedicated normalizer functions were added to `observation/pipeline/normalizer.py`:

- `normalize_process_exec(raw)` → `event_type = "process_exec"`, `source = "process"`
- `normalize_process_exit(raw)` → `event_type = "process_exit"`, `source = "process"`

Both follow the same common/extra split used by every other normalizer: network fields
(`src_ip`, `dst_ip`, etc.) are `None` since process events are not network events, and
process-specific fields (`exec_id`, `parent_exec_id`, `arguments`, `uid`, `cwd`, ...) are
carried in `extra`.

## 6. Verified Output

A live capture confirmed correct routing and normalization:

```text
Process exec : 178 events
Process exit : 574 events
```

Sample normalized record shape (fields abbreviated):

```json
{
  "timestamp": "2026-08-17T00:51:53.898977048Z",
  "event_type": "process_exec",
  "source": "process",
  "process": {"pid": 16923, "name": "/usr/bin/python3"},
  "extra": {
    "exec_id": "cGhhcmFoLUFTVVM6...",
    "parent_exec_id": "cGhhcmFoLUFTVVM6...",
    "parent_binary": "/usr/bin/python3",
    "arguments": "-u -m observation.collectors.tls_collector",
    "uid": 0,
    "cwd": "/home/User/ebpf-ml-threat-detector"
  }
}
```

## 7. Design Choice

Process exit is captured as a distinct event type rather than merged into the exec
record, since a process's lifetime (exec → exit) is itself a useful ML feature
(short-lived vs. long-running processes), and the two events are not guaranteed to be
observed in the same collection window.

`process_exec`/`process_exit` are the anchor that later correlation work joins network, file, and privilege activity onto, via `pid` and
`exec_id`.