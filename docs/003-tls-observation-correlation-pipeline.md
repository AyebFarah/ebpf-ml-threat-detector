# TLS Collector Documentation

## 1. Purpose

The TLS collector observes TLS ClientHello traffic and extracts information that cannot be obtained from a basic TCP connection.

Its main purpose is to enrich Tetragon network events with TLS-level information, especially SNI and JA4 fingerprinting.

## 2. Role in the Architecture

The TLS collector works as an enrichment source alongside Tetragon:

```text
Tetragon tcp_connect ─────┐
                          │
TLS ClientHello ──────────┤
                          ▼
                     Correlator
                          │
                          ▼
               correlated_events.jsonl
```

Tetragon tells us which process connected to which IP/port, while the TLS collector provides information about what TLS client was communicating and which hostname was requested.

## 3. TLS ClientHello

The collector focuses on the TLS ClientHello because it is sent at the beginning of a TLS connection and contains useful metadata about the client and requested connection.

Depending on the connection, the collector can extract:

- Source IP
- Source port
- Destination IP
- Destination port
- SNI
- TLS version
- JA4 fingerprint
- Timestamp

Example:

```json
{
  "event_type": "tls_client_hello",
  "src_ip": "192.168.1.10",
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "sni": "example.com",
  "ja4": "..."
}
```

## 4. SNI

SNI (Server Name Indication) identifies the hostname requested by the TLS client.

For example:

```text
dst_ip: 93.184.216.34
sni:     example.com
```

This is useful because the destination IP alone may not identify the actual service being accessed.

## 5. JA4 Fingerprint

The project uses JA4 rather than JA3 as the TLS fingerprint.

JA4 provides a standardized fingerprint derived from characteristics of the TLS ClientHello.

The fingerprint can help identify similarities between TLS clients and distinguish different applications or client behaviors.

The collector therefore preserves the JA4 value as part of the TLS event rather than making a detection decision itself.

## 6. Correlation With Tetragon

TLS events are correlated with Tetragon `tcp_connect` events using the connection's five-tuple:

- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `transport`

A time tolerance is also used because the TCP connection and TLS ClientHello are observed at slightly different times.

Conceptually:

```text
TCP connect
    │
    │ small time difference
    ▼
TLS ClientHello
```

A successful match allows the TLS information to be attached to the corresponding connection.

## 7. Result in correlated_events.jsonl

When correlation succeeds, the network event contains TLS information:

```json
{
  "network": {
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  },
  "tls": {
    "sni": "example.com",
    "ja4": "..."
  }
}
```

When no TLS event is matched:

```json
{
  "network": {
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  },
  "tls": null
}
```

The TCP connection is not discarded.

## 8. Why TLS Enrichment Is Important

Without TLS information, a network event may contain only:

```text
192.168.1.10 → 93.184.216.34:443
```

After TLS enrichment, it can contain:

```text
Process: /usr/bin/curl
Destination: 93.184.216.34:443
SNI: example.com
JA4: <fingerprint>
```

This provides significantly more context for later analysis.

## 9. ML Relevance

The TLS information can become part of the features used by the ML layer.

Potential features include:

- SNI
- JA4 fingerprint
- TLS version
- Destination IP
- Destination port
- Process identity
- Time between TCP connection and TLS ClientHello
- Whether TLS information was available

These features can help the model identify unusual or suspicious communication patterns.

## 10. Design Choice

The TLS collector is responsible only for observation and extraction:

```text
TLS traffic
    ↓
TLS Collector
    ↓
SNI + JA4 + TLS metadata
    ↓
Correlator
```

The final enriched event is produced by the correlator and stored in:

```text
samples/unified_events/correlated_events.jsonl
```
