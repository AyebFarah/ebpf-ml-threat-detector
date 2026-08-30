from observation.pipeline.correlator import (
    index_http_requests_by_tuple, index_http_responses_by_tuple,
    find_http_request_match, find_http_response_match,
    build_enriched_event, HTTP_CORRELATION_METHOD,
)

TCP_CONNECT = {
    "timestamp": "2026-08-20T10:00:00.000000000Z",
    "source": "tetragon", "event_type": "tcp_connect",
    "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34",
    "src_port": 51000, "dst_port": 80, "transport": "tcp",
    "direction": "outbound",
    "process": {"pid": 4242, "name": "curl"},
}

HTTP_REQUEST = {
    "timestamp": "2026-08-20T10:00:00.500000000Z",
    "source": "http", "event_type": "http_request",
    "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34",
    "src_port": 51000, "dst_port": 80, "transport": "tcp",
    "extra": {"method": "GET", "host": "example.com",
              "path_hash": "abc123", "path_length": 12,
              "user_agent_hash": "def456"},
}

HTTP_RESPONSE = {
    "timestamp": "2026-08-20T10:00:01.000000000Z",
    "source": "http", "event_type": "http_response",
    "src_ip": "93.184.216.34", "dst_ip": "10.0.0.5",
    "src_port": 80, "dst_port": 51000, "transport": "tcp",
    "extra": {"status_code": 200, "content_type": "text/html",
              "content_length": 128},
}


def test_request_matches_same_direction_as_connect():
    index = index_http_requests_by_tuple([HTTP_REQUEST])
    match, delta = find_http_request_match(TCP_CONNECT, index)
    assert match is not None
    assert match["extra"]["method"] == "GET"
    assert delta == 0.5


def test_response_matches_reversed_direction():
    index = index_http_responses_by_tuple([HTTP_RESPONSE])
    match, delta = find_http_response_match(TCP_CONNECT, index)
    assert match is not None
    assert match["extra"]["status_code"] == 200


def test_response_does_not_match_forward_tuple_index():
    """A response indexed and looked up with the SAME (unswapped) tuple
    should not accidentally match -- direction matters."""
    index = index_http_requests_by_tuple([HTTP_RESPONSE])  # wrong index on purpose
    match, _ = find_http_request_match(TCP_CONNECT, index)
    assert match is None


def test_build_enriched_event_merges_request_and_response():
    req_index = index_http_requests_by_tuple([HTTP_REQUEST])
    resp_index = index_http_responses_by_tuple([HTTP_RESPONSE])
    req_match, req_delta = find_http_request_match(TCP_CONNECT, req_index)
    resp_match, resp_delta = find_http_response_match(TCP_CONNECT, resp_index)

    event = build_enriched_event(
        TCP_CONNECT, None, None, None, None, None, None, None, None,
        None, [], [], req_match, resp_match, req_delta,
    )

    assert event["http"]["method"] == "GET"
    assert event["http"]["status_code"] == 200
    assert event["http"]["path_hash"] == "abc123"
    assert event["correlation"]["http_matched"] is True
    assert event["correlation"]["http_method"] == HTTP_CORRELATION_METHOD