# Cross-Signal Correlation Enrichment — Design and Implementation

## 1. Purpose

Prior to this work, every new collector (process lifecycle, sensitive file access,
privilege/capability, HTTP) wrote its normalized events into `unified_events.jsonl` as
a stream parallel to, but disconnected from, the existing DNS/TLS/SSH/TCP-flow
correlation already performed on `tcp_connect` events. 


 This work extends `observation/pipeline/correlator.py` to attach process lineage, nearby file activity,
nearby privilege activity, and HTTP request/response pairs onto each `tcp_connect`
event, alongside the DNS/TLS/SSH/TCP-flow matches already implemented.



## 2. Process Context Join

### Matching Strategy

For each `tcp_connect` event, the most recent `process_exec` event for the same `pid`
at or before the connect timestamp is selected as that connection's owning process
context, the same "most recent event at/before anchor timestamp" pattern already used
by `find_session_tcp_connect` for SSH session matching.


### Correlation Method Identifier

`PROCESS_CONTEXT_METHOD = "pid+most_recent_exec_before_connect"`

## 3. File and Privilege Activity Joins

### Matching Strategy — Time Window, Bidirectional

Unlike process context (which uses a strict "before" anchor), file and privilege
activity matching uses a **bidirectional time window** around the connection:

```python
FILE_ACTIVITY_TIME_WINDOW_SECONDS = 30
PRIVILEGE_ACTIVITY_TIME_WINDOW_SECONDS = 30

def find_nearby_events(tcp_event, index, window_seconds):
    """
    All events for the same pid within +/- window_seconds of the
    connection. Bidirectional on purpose: privilege escalation or file
    writes can precede OR follow the connection depending on the attack
    pattern (stage-then-connect vs connect-then-persist).
    """
```

This is a deliberate departure from the "before only" logic used elsewhere: privilege
escalation followed by a connection (staging, then reaching out) and a connection
followed by a persistence-file write (landing, then establishing a foothold) are both
real attack patterns, and a one-directional match would only catch one of them.

### Correlation Methods

`FILE_ACTIVITY_METHOD = "pid+time_window"`
`PRIVILEGE_ACTIVITY_METHOD = "pid+time_window"`

Both file and privilege matches are stored as **lists** on the enriched event
(`file_activity`, `privilege_activity`), not single best matches, multiple sensitive
file touches or multiple privilege events near one connection are all preserved, since
each is independently meaningful.

## 4. HTTP Request/Response Join

### Matching Strategy — Directional Tuple Reversal

HTTP requests travel in the same direction as the `tcp_connect` event (client →
server), so they are matched on the connection's own 5-tuple, the same convention
already used for TLS ClientHello matching.

HTTP responses travel in the *reverse* direction (server → client). The response index
is built on each response's own on-the-wire (src, dst) pair, and matching looks that
index up using the `tcp_connect` event's tuple **reversed**:


Both matches are merged into a single `http` block on the enriched event when either is
present, so a connection with only a captured request (response not observed in-window)
or only a captured response still surfaces the available half.

### Correlation Method

`HTTP_CORRELATION_METHOD = "five_tuple"`, tolerance `HTTP_TIME_TOLERANCE_SECONDS = 5`.

## 5. Enriched Event Shape

`build_enriched_event()` was extended with three additional top-level blocks beyond the
existing `dns` / `tls` / `ssh` / `tcp`:

```json
{
  "timestamp": "...",
  "process": {"pid": 4242, "name": "/usr/bin/python3"},
  "process_context": {
    "exec_id": "...",
    "parent_exec_id": "...",
    "parent_binary": "/bin/bash",
    "arguments": "update.py",
    "uid": 0,
    "cwd": "/tmp"
  },
  "file_activity": [
    {"timestamp": "...", "path": "/root/.ssh/authorized_keys", "operations": ["write"]}
  ],
  "privilege_activity": [
    {"timestamp": "...", "event_type": "sudo_exec", "detail": "sudo whoami"}
  ],
  "network": {"...": "..."},
  "dns": {"...": "..."},
  "tls": {"...": "..."},
  "ssh": null,
  "tcp": {"...": "..."},
  "http": {
    "method": "GET", "host": "example.com", "path_hash": "...",
    "status_code": 200, "content_type": "text/html"
  },
  "correlation": {
    "process_context_matched": true,
    "process_context_method": "pid+most_recent_exec_before_connect",
    "file_activity_count": 1,
    "file_activity_method": "pid+time_window",
    "privilege_activity_count": 1,
    "privilege_activity_method": "pid+time_window",
    "http_matched": true,
    "http_method": "five_tuple",
    "http_time_delta_ms": 500
  }
}
```

The `correlation` block's existing fields (`dns_matched`, `tls_matched`, etc.) are
unchanged; the new fields follow the same naming convention
(`<signal>_matched`/`<signal>_method`, or `<signal>_count` for list-valued matches).

## 6. DNS Response Latency

Separately, DNS response latency was added as a normalizer-level enrichment.

### Matching Key

Query and response are paired by `(transaction_id, client_ip, resolver_ip)`, with the
response's `(src_ip, dst_ip)` reversed relative to the query's, since a 16-bit DNS
transaction ID can repeat across unrelated query/response pairs and must be
disambiguated by the IP pair.


### Output

Each `dns_response` event's `extra` gains a `response_latency_ms` field, the delta
between the matched query and the response, in milliseconds, or `null` if no matching
query was found in the same run.

This runs as its own pass over all DNS events (`attach_dns_response_latency`) rather
than through the generic per-line normalizer dispatch, since it requires seeing the
full set of query and response events before pairing them, the same reason the
capability-aggregation step (documented separately) also runs as a dedicated pass.

## 7. Verification

Live capture confirmed:

- `process_context` populated with real `exec_id`/`arguments`/`parent_binary` for
  connections made by collector subprocesses spawned during a pipeline run.
- `file_activity` populated when a sensitive file access occurred within the matching
  window of a connection from the same process.
- `http` block correctly merging both the request (`method`, `host`, `path_hash`) and
  response (`status_code`) halves of a single exchange, confirming the tuple-reversal
  logic for response matching works as designed.
- `response_latency_ms` populated with small positive millisecond values for local
  resolver round trips.

## 8. Design Principle Established

Two distinct matching strategies are now used depending on the semantics of the
relationship being modeled: a **strict "most recent before"** anchor for events that
necessarily precede the network activity they explain (process ownership), and a
**bidirectional time window** for events whose order relative to the connection is
itself meaningful signal (file/privilege activity, which can precede or follow
depending on the attack pattern). 