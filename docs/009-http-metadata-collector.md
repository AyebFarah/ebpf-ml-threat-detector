# HTTP Metadata Collector — Design and Implementation

## 1. Purpose

The HTTP collector adds application-layer semantics for unencrypted HTTP traffic, useful for
"download, C2, suspicious request patterns" detection, while remaining explicit that
HTTP is a secondary signal, not a primary one, since most modern traffic is encrypted
and already covered by the TLS/JA4 collector.

## 2. Architecture Decision — Scapy Sniffer, Not a TracingPolicy

Unlike the file-access, privilege, and capability collectors, HTTP metadata is captured
via a userspace packet sniffer (`observation/collectors/http_collector.py`), following
the same `scapy`-based design as `dns_collector.py`, rather than a Tetragon
`TracingPolicy`.

This is a deliberate architectural choice: a kprobe on `tcp_sendmsg` can observe that
*some* payload was sent on port 80, but cannot parse whether that payload is a valid
HTTP request, extract its method/host/headers, or distinguish a request from a
response. HTTP is fundamentally an application-layer protocol; only a packet-content
parser operating on captured bytes can extract it, which is exactly the pattern already
proven for DNS.

## 3. Explicit Scope Limits

The collector is deliberately minimal:

- **No request or response body capture**, ever — only headers are parsed.
- **Path and User-Agent are hashed**, never stored raw:
- **Best-effort single-packet parsing only.** If HTTP headers span multiple TCP
  segments, the packet is skipped rather than reassembled, full stream reassembly was
  judged unnecessary complexity for a secondary-signal.
- **Plain HTTP only (port 80), not HTTPS.** Encrypted traffic is already covered by the
  TLS collector's SNI/JA4/handshake extraction; this collector only adds value for the
  shrinking slice of unencrypted HTTP still observed on the network.
- **Not registered as a critical process.** `http_collector` is deliberately excluded
  from `bootstrap.CRITICAL_PROCESSES` — if it crashes, the rest of the pipeline
  continues running, consistent with its role as supplementary rather than core
  telemetry.

## 4. Collected Information

### `http_request`

| Field | Notes |
|---|---|
| `method`, `http_version` | Parsed from the request line |
| `host` | From the `Host` header, stored in plaintext (not sensitive on its own) |
| `path_hash` | SHA-256 (truncated), never the raw path |
| `path_length` | Raw path length as a numeric feature, independent of the hash |
| `user_agent_hash` | SHA-256 (truncated) of the `User-Agent` header, if present |
| `content_length` | From the `Content-Length` header, if present |

### `http_response`

| Field | Notes |
|---|---|
| `status_code`, `http_version` | Parsed from the status line |
| `content_type`, `content_length` | From response headers |

## 5. Parsing Approach

Header parsing uses targeted regular expressions rather than a full HTTP parser
library, matching the collector's intentionally minimal scope:

```python
REQUEST_LINE_RE = re.compile(
    rb"^(?P<method>[A-Z]{3,10}) (?P<path>\S+) HTTP/(?P<version>\d\.\d)\r\n"
)
RESPONSE_LINE_RE = re.compile(
    rb"^HTTP/(?P<version>\d\.\d) (?P<status>\d{3}) "
)
```

A packet is only processed once a complete header block (terminated by `\r\n\r\n`) is
present in a single captured segment:

```python
def split_head(payload: bytes):
    idx = payload.find(b"\r\n\r\n")
    if idx == -1:
        return None, False
    return payload[: idx + 4], True
```

## 6. Integration with the Pipeline

Registered in `observation/runtime/bootstrap.py`'s `build_commands()` alongside the
other collectors, writing to:

```text
samples/collectors_events/http_events.jsonl
```

`normalize_http(raw)` in the normalizer follows the same common/extra split used by
every other network-sourced collector: `source = "http"`, `event_type` is either
`"http_request"` or `"http_response"`.

## 7. Verified Output

Live capture against `neverssl.com` (chosen because it is designed to never redirect to
HTTPS, unlike most modern sites) confirmed correct request/response pairing, with
`path_hash` populated instead of a raw path and `host` correctly extracted.

## 8. Design Choice

The collector intentionally trades completeness (no reassembly, headers only, plain
HTTP only) for simplicity and safety. Given HTTP is explicitly a secondary signal in
this project's threat model, the cost/benefit of building a full reassembling HTTP
parser was judged not to justify the added complexity at this stage.