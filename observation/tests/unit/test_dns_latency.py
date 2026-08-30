from observation.pipeline.normalizer import normalize_dns, attach_dns_response_latency

QUERY = {
    "timestamp": "2026-08-20T12:00:00.000000000Z",
    "event_type": "dns_query",
    "src_ip": "10.0.0.5", "dst_ip": "192.168.0.1",
    "src_port": 51234, "dst_port": 53, "transport": "udp", "direction": "outbound",
    "query_name": "example.com", "query_type": 1, "transaction_id": 42,
}

RESPONSE = {
    "timestamp": "2026-08-20T12:00:00.150000000Z",
    "event_type": "dns_response",
    "src_ip": "192.168.0.1", "dst_ip": "10.0.0.5",
    "src_port": 53, "dst_port": 51234, "transport": "udp", "direction": "inbound",
    "transaction_id": 42, "rcode": 0, "query_name": "example.com",
    "answer_count": 1, "answers": [], "resolved_ip": "93.184.216.34",
}

UNMATCHED_RESPONSE = {
    **RESPONSE,
    "transaction_id": 999,
}


def test_response_latency_computed_for_matching_pair():
    query = normalize_dns(QUERY)
    response = normalize_dns(RESPONSE)
    events = attach_dns_response_latency([query, response])

    resp = [e for e in events if e["event_type"] == "dns_response"][0]
    assert resp["extra"]["response_latency_ms"] == 150.0


def test_response_latency_is_none_when_no_matching_query():
    response = normalize_dns(UNMATCHED_RESPONSE)
    events = attach_dns_response_latency([response])

    resp = events[0]
    assert resp["extra"]["response_latency_ms"] is None


def test_same_transaction_id_different_ip_pairs_do_not_cross_match():
    """Two unrelated query/response pairs sharing a transaction_id
    (16-bit IDs repeat) must not be matched to each other."""
    query_a = normalize_dns(QUERY)  # 10.0.0.5 <-> 192.168.0.1
    response_b = normalize_dns({
        **RESPONSE,
        "src_ip": "192.168.0.1", "dst_ip": "10.0.0.99",  # different client
    })
    events = attach_dns_response_latency([query_a, response_b])

    resp = [e for e in events if e["event_type"] == "dns_response"][0]
    assert resp["extra"]["response_latency_ms"] is None