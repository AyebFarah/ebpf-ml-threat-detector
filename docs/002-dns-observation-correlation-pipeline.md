# DNS Collector Documentation

## 1. Purpose

The DNS collector is responsible for observing DNS activity and extracting information that is not directly available from the low-level network events collected by Tetragon.

The main goal is to establish the relationship:

```text
Domain name → Resolved IP address
```

This information is later used to enrich `tcp_connect` events.

For example, Tetragon may observe:

```text
192.168.1.10 → 93.184.216.34:443
```

but it does not inherently tell us that:

```text
93.184.216.34 = example.com
```

The DNS collector provides this missing context.

## 2. Role in the Architecture

The DNS collector is part of the observation layer:

```text
                    ┌──────────────────┐
                    │     Tetragon     │
                    │   tcp_connect    │
                    └────────┬─────────┘
                             │
                             │
                    ┌────────▼─────────┐
                    │      DNS         │
                    │    Collector     │
                    └────────┬─────────┘
                             │
                             ▼
                       Correlator
                             │
                             ▼
                  correlated_events.jsonl
```

The collector does not replace Tetragon.

Instead, the two sources provide different types of information:

| Source | Information |
|---|---|
| Tetragon | Actual network connection |
| DNS collector | Domain → IP resolution |
| Correlator | Combines both |

This separation allows the project to preserve the original observations while adding higher-level context later.

## 3. DNS Events Collected

The collector handles both DNS queries and DNS responses.

### DNS Query

A DNS query represents a request to resolve a domain.

For example:

```text
Client → DNS server
"example.com"
```

The collector records information such as:

- timestamp
- queried domain
- source IP
- DNS server
- query information

A simplified event looks like:

```json
{
  "event_type": "dns_query",
  "domain": "example.com",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.1"
}
```

### DNS Response

The response contains the information that is particularly important for correlation:

```text
example.com → 93.184.216.34
```

The collector extracts:

- domain
- resolved IP address
- TTL
- timestamp
- response information

Example:

```json
{
  "event_type": "dns_response",
  "domain": "example.com",
  "resolved_ip": "93.184.216.34",
  "ttl": 300
}
```

The response is more important for network correlation because Tetragon provides the destination IP, not the destination domain.

## 4. Why Both Query and Response Events Are Kept

The collector does not only store the final IP address.

Both sides of the DNS transaction are useful.

For example:

```text
09:00:00  DNS query
           example.com
09:00:00  DNS response
           example.com → 93.184.216.34
09:00:01  TCP connection
           192.168.1.10 → 93.184.216.34:443
```

Keeping these events allows the pipeline to preserve the original observation sequence.

It also gives the ML layer access to DNS-related features later instead of discarding the original DNS activity.

## 5. Resolved IP Address

The `resolved_ip` field is one of the most important fields produced by the DNS collector.

Example:

```json
{
  "domain": "example.com",
  "resolved_ip": "93.184.216.34"
}
```

This creates the link required by the correlator:

```text
DNS:
example.com → 93.184.216.34
        ↓
Tetragon:
connection → 93.184.216.34:443
```

The correlator can therefore associate the connection with `example.com`.

## 6. TTL

The collector also preserves the DNS TTL when it is available.

TTL indicates how long a DNS response can normally be cached.

For example:

```json
{
  "domain": "example.com",
  "resolved_ip": "93.184.216.34",
  "ttl": 60
}
```

TTL is not currently used as the primary correlation key.

It is preserved because it can become a useful feature for the later detection layer.

For example, DNS behavior involving frequently changing IP addresses may be interesting when combined with other observations.

The collector therefore observes and preserves the information rather than prematurely turning it into a detection decision.

## 7. Correlation With Tetragon

The DNS collector itself does not decide whether a connection is suspicious.

That responsibility belongs to the correlator.

The correlation strategy is:

```text
resolved_ip + time window
```

The basic process is:

1. Collect DNS responses.
2. Index responses by their `resolved_ip`.
3. Observe a Tetragon `tcp_connect`.
4. Take the connection's `dst_ip`.
5. Search for a recent DNS response resolving to that IP.
6. If a suitable response is found, attach the DNS information to the connection.

For example:

```text
DNS response
timestamp:   09:00:00
domain:      example.com
resolved_ip: 93.184.216.34
followed by:
Tetragon tcp_connect
timestamp: 09:00:01
dst_ip:    93.184.216.34
dst_port:  443
```

produces an enriched connection containing DNS information.

## 8. Why a Time Window Is Necessary

An IP address can be associated with different domains, especially when infrastructure is shared.

Therefore, matching only:

```text
resolved_ip == dst_ip
```

would be too weak.

The correlation also considers the timing of the events.

Conceptually:

```text
DNS response
     │
     │ small time difference
     ▼
TCP connection
```

This makes it more likely that the DNS response is related to the observed connection.

The correlator therefore uses:

```text
resolved_ip + temporal proximity
```

rather than IP matching alone.

## 9. Result in correlated_events.jsonl

DNS information is ultimately attached to the network event in the correlated dataset.

A connection without a DNS match may look like:

```json
{
  "network": {
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  },
  "dns": null
}
```

When a DNS correlation succeeds, the event can contain DNS information instead:

```json
{
  "network": {
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  },
  "dns": {
    "domain": "example.com",
    "resolved_ip": "93.184.216.34",
    "ttl": 300
  }
}
```

The important point is that the original network event remains present. DNS acts as enrichment.

## 10. Why Some Connections Have No DNS Match

A missing DNS match does not necessarily mean that the DNS collector failed.

A connection can legitimately have:

```json
"dns": null
```

For example:

- the application uses a cached DNS result
- the DNS lookup happened before the observation window
- the connection uses a hard-coded IP address
- the DNS event was not captured
- the IP was resolved by another mechanism
- the DNS response fell outside the correlation time window

Therefore, the correlator should preserve the connection rather than discard it.

This is important for the ML dataset: absence of DNS information is itself potentially meaningful and should not cause the network event to disappear.

## 11. Design Choice: Collector vs. Correlator

The DNS collector is intentionally kept separate from the correlator.

**DNS collector** is responsible for:

```text
Observe DNS
    ↓
Extract DNS information
    ↓
Write DNS events
```

**Correlator** is responsible for:

```text
Read DNS events
+
Read Tetragon events
    ↓
Find relationships
    ↓
Create enriched events
```

This separation makes each component easier to test and prevents the collector from containing correlation logic.

## 12. ML Relevance

DNS information will eventually become part of the features available to the ML layer through the correlated dataset.

Potential features include:

- destination domain
- resolved IP
- DNS query frequency
- DNS response frequency
- TTL
- relationship between domain and IP
- time between DNS resolution and connection
- whether a connection had a corresponding DNS resolution

For example, the ML pipeline could eventually see:

```text
Process:       /usr/bin/curl
Destination:   93.184.216.34:443
Domain:        example.com
TLS:           available
DNS TTL:       60
DNS→TCP Δt:    120 ms
```

instead of only:

```text
93.184.216.34:443
```

This is the main reason the DNS collector is valuable: it transforms otherwise low-level IP-based network observations into richer, contextual network events without making the detection decision itself.

## 13. Final Data Flow

The complete DNS path is:

```text
              DNS traffic
                  │
                  ▼
          ┌───────────────┐
          │ DNS Collector │
          └───────┬───────┘
                  │
          dns_query / dns_response
                  │
                  ▼
           Normalizer
                  │
                  │
                  ├───────────────┐
                  │               │
                  ▼               ▼
             DNS events     Tetragon events
                  │               │
                  └───────┬───────┘
                          ▼
                     Correlator
                          │
                          ▼
                correlated_events.jsonl
                          │
                          ▼
                       ML data
```
