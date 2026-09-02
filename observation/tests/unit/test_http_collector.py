from ...collectors.http_collector import (
    split_head, parse_headers, hash_value,
    REQUEST_LINE_RE, RESPONSE_LINE_RE,
)

SAMPLE_REQUEST = (
    b"GET /api/users?id=42 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: curl/8.4.0\r\n"
    b"\r\n"
)

SAMPLE_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 128\r\n"
    b"\r\n"
)

SAMPLE_BODY_ONLY = b'{"partial": "body chunk with no headers"}'


def test_split_head_finds_complete_header_block():
    head, found = split_head(SAMPLE_REQUEST)
    assert found is True
    assert head.endswith(b"\r\n\r\n")


def test_split_head_rejects_body_only_segment():
    head, found = split_head(SAMPLE_BODY_ONLY)
    assert found is False
    assert head is None


def test_parse_headers_extracts_host_and_user_agent():
    headers = parse_headers(SAMPLE_REQUEST)
    assert headers["host"] == "example.com"
    assert headers["user-agent"] == "curl/8.4.0"


def test_hash_value_is_deterministic_and_not_raw():
    h1 = hash_value("/api/users?id=42")
    h2 = hash_value("/api/users?id=42")
    assert h1 == h2
    assert "/api/users" not in h1


def test_hash_value_differs_for_different_paths():
    assert hash_value("/api/users") != hash_value("/api/orders")


def test_request_line_regex_matches_get():
    match = REQUEST_LINE_RE.match(SAMPLE_REQUEST)
    assert match is not None
    assert match.group("method") == b"GET"
    assert match.group("version") == b"1.1"


def test_response_line_regex_matches_200():
    match = RESPONSE_LINE_RE.match(SAMPLE_RESPONSE)
    assert match is not None
    assert match.group("status") == b"200"