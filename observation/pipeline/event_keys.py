"""Deterministic identity keys for raw and correlated events, used to
deduplicate the same real-world event when it appears in more than one
place, e.g. a file/privilege event attached to multiple nearby
correlated_events via the correlator's ±30s window, or a DNS/TCP event
appearing in both its raw collector table and a correlated_events-derived
row. Keys are content hashes, not synthetic/random IDs, so the same real
event always produces the same key regardless of which code path computed
it.
"""

import hashlib


def make_source_event_key(raw_event: dict) -> str:
    """Stable identity for a raw file/privilege event, independent of
    which correlated_event(s) it ends up attached to. Needed because
    find_nearby_events() can legitimately attach the same real event to
    multiple nearby tcp_connect events within its ±window_seconds, this
    key lets downstream aggregation dedupe those repeated attachments
    back down to the single real occurrence they represent."""
    extra = raw_event.get("extra", {}) or {}
    pid = (raw_event.get("process") or {}).get("pid")
    raw = f"{raw_event.get('timestamp')}|{raw_event.get('event_type')}|{pid}|{extra.get('path','')}|{extra.get('arguments','')}|{extra.get('capability','')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]



def make_dns_dedup_key(event: dict) -> str:
    """DNS query/response identity. transaction_id alone repeats across
    unrelated queries, src_ip/dst_ip/query_name/timestamp disambiguate."""
    raw = (
        f"{event.get('transaction_id')}|{event.get('src_ip')}|{event.get('dst_ip')}|"
        f"{event.get('query_name')}|{event.get('timestamp')}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def make_tcp_flow_dedup_key(event: dict) -> str:
    """TCP flow identity, for dedup when merging tcp_flows_raw with
    correlated_events-derived flow rows."""
    raw = (
        f"{event.get('src_ip')}|{event.get('src_port')}|{event.get('dst_ip')}|"
        f"{event.get('dst_port')}|{event.get('start_ts')}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]