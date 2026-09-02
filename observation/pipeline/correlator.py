import json
from datetime import datetime
from .. import paths

INPUT_FILE = paths.UNIFIED_EVENTS_FILE
OUTPUT_FILE = paths.CORRELATED_EVENTS_FILE
SSH_SESSIONS_OUTPUT_FILE = paths.SSH_SESSIONS_FILE

DNS_TIME_WINDOW_SECONDS = 5
TLS_TIME_TOLERANCE_SECONDS = 5
SSH_TIME_TOLERANCE_SECONDS = 5
TCP_FLOW_TIME_TOLERANCE_SECONDS = 5
FILE_ACTIVITY_TIME_WINDOW_SECONDS = 30
PRIVILEGE_ACTIVITY_TIME_WINDOW_SECONDS = 30
HTTP_TIME_TOLERANCE_SECONDS = 5


HTTP_CORRELATION_METHOD = "five_tuple"
TCP_FLOW_CORRELATION_METHOD = "five_tuple+start_ts"
DNS_CORRELATION_METHOD = "resolved_ip+time"
TLS_CORRELATION_METHOD = "five_tuple"
SSH_CORRELATION_METHOD = "src_ip+src_port+dst_port22+time"
PROCESS_CONTEXT_METHOD = "pid+most_recent_exec_before_connect"
FILE_ACTIVITY_METHOD = "pid+time_window"
PRIVILEGE_ACTIVITY_METHOD = "pid+time_window"

SSH_PORT = 22


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_events(path: paths) -> list:
    events = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


# ---------------------------------------------------------------------------
# Per-tcp_connect correlation (DNS / TLS / SSH). Produces
# correlated_events.jsonl.
# ---------------------------------------------------------------------------

def split_by_source(events: list):
    dns_responses = [e for e in events if e["source"] == "dns" and e["event_type"] == "dns_response"]
    tcp_connects = [e for e in events if e["source"] == "tetragon" and e["event_type"] == "tcp_connect"]
    tls_hellos = [e for e in events if e["source"] == "tls" and e["event_type"] == "tls_client_hello"]
    ssh_auth_success = [e for e in events if e["source"] == "ssh" and e["event_type"] == "ssh_auth_success"]
    tcp_flows = [e for e in events if e["source"] == "tcp" and e["event_type"] == "tcp_flow"]
    http_requests = [e for e in events if e["source"] == "http" and e["event_type"] == "http_request"]
    http_responses = [e for e in events if e["source"] == "http" and e["event_type"] == "http_response"]
    return dns_responses, tcp_connects, tls_hellos, ssh_auth_success, tcp_flows, http_requests, http_responses


def index_dns_by_ip(dns_responses: list) -> dict:
    index = {}
    for dns in dns_responses:
        for answer in dns.get("extra", {}).get("answers", []):
            if answer.get("type") not in ("A", "AAAA"):
                continue
            resolved_ip = answer.get("value")
            if not resolved_ip:
                continue
            index.setdefault(resolved_ip, []).append(dns)
    for ip in index:
        index[ip].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def index_tls_by_tuple(tls_hellos: list) -> dict:
    index = {}
    for tls in tls_hellos:
        key = (tls["src_ip"], tls["dst_ip"], tls["src_port"], tls["dst_port"], tls["transport"])
        index.setdefault(key, []).append(tls)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def index_ssh_by_src(ssh_events: list) -> dict:
    index = {}
    for ssh in ssh_events:
        if ssh.get("src_ip") is None or ssh.get("src_port") is None:
            continue
        key = (ssh["src_ip"], ssh["src_port"])
        index.setdefault(key, []).append(ssh)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index
def index_ssh_sessions_by_connection(sessions: list) -> dict:
    """
    Index SSH sessions by source IP and source port.

    A TCP connection's source IP + source port identifies the SSH
    connection in our current local observation model.
    """
    index = {}

    for session in sessions:
        key = (session.get("src_ip"), session.get("src_port"))

        if None in key:
            continue

        index.setdefault(key, []).append(session)

    for key in index:
        index[key].sort(
            key=lambda s: parse_ts(s["earliest_event_ts"])
        )

    return index

def build_ssh_correlation_block(session: dict, tcp_event: dict) -> dict:
    """
    Convert an SSH session into the compact SSH information that will
    become part of the canonical correlated event.
    """

    event_types = session.get("event_types_seen", [])

    auth_failures = event_types.count("ssh_auth_failure")
    auth_success = session.get("auth_success_ts") is not None

    return {
        "session_key": session.get("session_key"),
        "username": session.get("username"),

        "auth_attempts": auth_failures + (1 if auth_success else 0),
        "auth_failures": auth_failures,
        "auth_success": auth_success,
        "auth_method": session.get("auth_method"),

        "session_opened": session.get("session_opened_ts") is not None,
        "session_opened_ts": session.get("session_opened_ts"),

        "session_closed": session.get("session_closed_ts") is not None,
        "session_closed_ts": session.get("session_closed_ts"),
        "session_duration_seconds": session.get("session_duration_seconds"),

        "disconnected": session.get("disconnected_ts") is not None,
        "disconnected_ts": session.get("disconnected_ts"),

        "tcp_connect_matched": session.get("tcp_connect_matched"),
        "tcp_close_matched": session.get("tcp_close_matched"),
        "connection_duration_seconds": session.get(
            "connection_duration_seconds"
        ),

        "execve_matched": session.get("execve_matched"),
        "execve_binary": session.get("execve_binary"),
    }

def find_dns_match(tcp_event, dns_index):
    candidates = dns_index.get(tcp_event["dst_ip"], [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    best, best_delta = None, None
    for dns in candidates:
        delta = (tcp_ts - parse_ts(dns["timestamp"])).total_seconds()
        if 0 <= delta <= DNS_TIME_WINDOW_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = dns, delta
        elif delta < 0:
            break
    return best, best_delta


def find_tls_match(tcp_event, tls_index):
    key = (tcp_event["src_ip"], tcp_event["dst_ip"], tcp_event["src_port"],
           tcp_event["dst_port"], tcp_event["transport"])
    candidates = tls_index.get(key, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    best, best_delta = None, None
    for tls in candidates:
        delta = (parse_ts(tls["timestamp"]) - tcp_ts).total_seconds()
        if 0 <= delta <= TLS_TIME_TOLERANCE_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = tls, delta
    return best, best_delta


def find_ssh_match(tcp_event, ssh_index):
    if tcp_event.get("dst_port") != SSH_PORT:
        return None, None
    key = (tcp_event["src_ip"], tcp_event["src_port"])
    candidates = ssh_index.get(key, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])

    best, best_delta = None, None
    for ssh in candidates:  # sorted ascending by timestamp
        delta = (parse_ts(ssh["timestamp"]) - tcp_ts).total_seconds()
        if delta >= 0:  # auth must happen at/after the connect, no upper bound
            if best is None or delta < best_delta:
                best, best_delta = ssh, delta
    return best, best_delta


def build_enriched_event(tcp_event, dns_match, dns_delta, tls_match, tls_delta, ssh_match, ssh_delta,
                         tcp_flow_match, tcp_flow_delta, process_context, file_matches, privilege_matches,
                         http_request_match, http_response_match, http_delta):
    dns_block = None
    if dns_match:
        dns_block = dict(dns_match["extra"])
        dns_block["timestamp"] = dns_match["timestamp"]
    tls_block = None
    if tls_match:
        tls_block = dict(tls_match["extra"])
        tls_block["timestamp"] = tls_match["timestamp"]
    ssh_block = None
    if ssh_match:
        ssh_block = dict(ssh_match["extra"])
        ssh_block["timestamp"] = ssh_match["timestamp"]
        ssh_block["dst_ip"] = tcp_event.get("dst_ip")
    tcp_block = None
    if tcp_flow_match:
        tcp_block = dict(tcp_flow_match["extra"])

    process_context_block = None
    if process_context:
        ctx_extra = process_context.get("extra", {})
        process_context_block = {
            "exec_id": ctx_extra.get("exec_id"),
            "parent_exec_id": ctx_extra.get("parent_exec_id"),
            "parent_binary": ctx_extra.get("parent_binary"),
            "arguments": ctx_extra.get("arguments"),
            "uid": ctx_extra.get("uid"),
            "cwd": ctx_extra.get("cwd"),
            "start_time": ctx_extra.get("start_time"),
        }

    file_activity_block = [
        {
            "timestamp": f["timestamp"],
            "path": f.get("extra", {}).get("path"),
            "operations": f.get("extra", {}).get("operations"),
        }
        for f in file_matches
    ]

    privilege_activity_block = [
        {
            "timestamp": p["timestamp"],
            "event_type": p["event_type"],
            "detail": (
                p.get("extra", {}).get("arguments")
                if p["event_type"] == "sudo_exec"
                else p.get("extra", {}).get("capability")
            ),
        }
        for p in privilege_matches
    ]

    http_block = None
    if http_request_match or http_response_match:
        http_block = {}
        if http_request_match:
            http_block.update({
                "method": http_request_match.get("extra", {}).get("method"),
                "host": http_request_match.get("extra", {}).get("host"),
                "path_hash": http_request_match.get("extra", {}).get("path_hash"),
                "path_length": http_request_match.get("extra", {}).get("path_length"),
                "user_agent_hash": http_request_match.get("extra", {}).get("user_agent_hash"),
                "request_timestamp": http_request_match["timestamp"],
            })
        if http_response_match:
            http_block.update({
                "status_code": http_response_match.get("extra", {}).get("status_code"),
                "content_type": http_response_match.get("extra", {}).get("content_type"),
                "content_length": http_response_match.get("extra", {}).get("content_length"),
                "response_timestamp": http_response_match["timestamp"],
            })

    return {
        "timestamp": tcp_event["timestamp"],
        "process": tcp_event.get("process"),
        "process_context": process_context_block,
        "file_activity": file_activity_block,
        "privilege_activity": privilege_activity_block,

        "network": {
            "src_ip": tcp_event["src_ip"],
            "dst_ip": tcp_event["dst_ip"],
            "src_port": tcp_event["src_port"],
            "dst_port": tcp_event["dst_port"],
            "transport": tcp_event["transport"],
            "direction": tcp_event.get("direction"),
        },

        "dns": dns_block,
        "tls": tls_block,
        "ssh": None,
        "tcp": tcp_block,
        "http": http_block,

        "correlation": {
            "dns_matched": dns_match is not None,
            "dns_method": DNS_CORRELATION_METHOD,
            "dns_time_delta_ms": round(dns_delta * 1000) if dns_delta is not None else None,

            "tls_matched": tls_match is not None,
            "tls_method": TLS_CORRELATION_METHOD,
            "tls_time_delta_ms": round(tls_delta * 1000) if tls_delta is not None else None,

            "ssh_matched": ssh_match is not None,
            "ssh_method": SSH_CORRELATION_METHOD,
            "ssh_time_delta_ms": round(ssh_delta * 1000) if ssh_delta is not None else None,

            "tcp_flow_matched": tcp_flow_match is not None,
            "tcp_flow_method": TCP_FLOW_CORRELATION_METHOD,
            "tcp_flow_time_delta_ms": round(tcp_flow_delta * 1000) if tcp_flow_delta is not None else None,

            "process_context_matched": process_context is not None,
            "process_context_method": PROCESS_CONTEXT_METHOD,

            "file_activity_count": len(file_matches),
            "file_activity_method": FILE_ACTIVITY_METHOD,

            "privilege_activity_count": len(privilege_matches),
            "privilege_activity_method": PRIVILEGE_ACTIVITY_METHOD,

            "http_matched": http_block is not None,
            "http_method": HTTP_CORRELATION_METHOD,
            "http_time_delta_ms": round(http_delta * 1000) if http_delta is not None else None,
        },
    }

def correlate(events: list) -> list:
    dns_responses, tcp_connects, tls_hellos, ssh_events, tcp_flows, http_requests, http_responses = split_by_source(events)

    dns_index = index_dns_by_ip(dns_responses)
    tls_index = index_tls_by_tuple(tls_hellos)
    ssh_index = index_ssh_by_src(ssh_events)
    tcp_flow_index = index_tcp_flows_by_tuple(tcp_flows)
    http_request_index = index_http_requests_by_tuple(http_requests)
    http_response_index = index_http_responses_by_tuple(http_responses)

    process_index = index_process_exec_by_pid(events)
    file_index = index_events_by_pid(events, "file", {"file_access"})
    privilege_index = index_events_by_pid(events, "privilege", {"sudo_exec", "capability_use"})

    ssh_sessions, _ = build_ssh_sessions(events)
    ssh_sessions_index = index_ssh_sessions_by_connection(ssh_sessions)

    enriched = []

    for tcp_event in tcp_connects:
        dns_match, dns_delta = find_dns_match(tcp_event, dns_index)
        tls_match, tls_delta = find_tls_match(tcp_event, tls_index)
        ssh_match, ssh_delta = find_ssh_match(tcp_event, ssh_index)
        tcp_flow_match, tcp_flow_delta = find_tcp_flow_match(tcp_event, tcp_flow_index)

        process_context = find_process_context(tcp_event, process_index)
        file_matches = find_nearby_events(tcp_event, file_index, FILE_ACTIVITY_TIME_WINDOW_SECONDS)
        privilege_matches = find_nearby_events(tcp_event, privilege_index, PRIVILEGE_ACTIVITY_TIME_WINDOW_SECONDS)

        http_request_match, http_req_delta = find_http_request_match(tcp_event, http_request_index)
        http_response_match, http_resp_delta = find_http_response_match(tcp_event, http_response_index)
        http_delta = http_req_delta if http_req_delta is not None else http_resp_delta

        ssh_session = None
        if tcp_event.get("dst_port") == SSH_PORT:
            key = (tcp_event.get("src_ip"), tcp_event.get("src_port"))
            candidates = ssh_sessions_index.get(key, [])
            tcp_ts = parse_ts(tcp_event["timestamp"])
            best = None
            for session in candidates:
                if parse_ts(session["earliest_event_ts"]) >= tcp_ts:
                    best = session
                    break
            if best is None:
                for session in reversed(candidates):
                    if parse_ts(session["earliest_event_ts"]) < tcp_ts:
                        best = session
                        break
            ssh_session = best

        ssh_block = None
        if ssh_session is not None:
            ssh_block = build_ssh_correlation_block(ssh_session, tcp_event)

        event = build_enriched_event(
            tcp_event, dns_match, dns_delta, tls_match, tls_delta,
            ssh_match, ssh_delta, tcp_flow_match, tcp_flow_delta,
            process_context, file_matches, privilege_matches,
            http_request_match, http_response_match, http_delta,
        )

        if ssh_block is not None:
            event["ssh"] = ssh_block
            event["correlation"]["ssh_matched"] = True
            event["correlation"]["ssh_method"] = "src_ip+src_port+ssh_session"

        enriched.append(event)

    return enriched

def build_ssh_sessions(events: list):
    ssh_events = [e for e in events if e["source"] == "ssh"]

    grouped = {}
    orphans = []
    for e in ssh_events:
        key = e.get("extra", {}).get("session_key") or e.get("session_key")
        if key is None:
            orphans.append(e)
            continue
        grouped.setdefault(key, []).append(e)

    sessions = []
    for key, evs in grouped.items():
        evs.sort(key=lambda e: parse_ts(e["timestamp"]))
        record = {
            "session_key": key,
            "username": evs[0].get("extra", {}).get("username") or evs[0].get("username"),
            "src_ip": evs[0]["src_ip"],
            "src_port": evs[0]["src_port"],
            "pid": evs[0].get("process", {}).get("pid") if evs[0].get("process") else None,
            "event_types_seen": [e["event_type"] for e in evs],
            "earliest_event_ts": evs[0]["timestamp"],
            "auth_success_ts": None,
            "auth_method": None,
            "session_opened_ts": None,
            "session_closed_ts": None,
            "session_duration_seconds": None,
            "disconnected_ts": None,
        }
        for e in evs:
            extra = e.get("extra", {})
            et = e["event_type"]
            if et == "ssh_auth_success":
                record["auth_success_ts"] = e["timestamp"]
                record["auth_method"] = extra.get("auth_method")
            elif et == "ssh_session_opened":
                record["session_opened_ts"] = e["timestamp"]
            elif et == "ssh_session_closed":
                record["session_closed_ts"] = e["timestamp"]
                record["session_duration_seconds"] = extra.get("session_duration_seconds")
            elif et == "ssh_disconnected":
                record["disconnected_ts"] = e["timestamp"]
        sessions.append(record)

    return sessions, orphans

def index_tcp_events_by_tuple(events: list) -> dict:
    """Index normalized tetragon tcp events (connect or close) by their
    5-tuple, sorted by time."""
    index = {}
    for e in events:
        key = (e["src_ip"], e["dst_ip"], e["src_port"], e["dst_port"], e["transport"])
        index.setdefault(key, []).append(e)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def find_session_tcp_connect(session: dict, tcp_connects_by_src: dict):
    """Match a session to the Tetragon tcp_connect on the same 5-tuple that
    occurred before any SSH activity was observed for it. TCP connect always
    precedes authentication, sometimes by many seconds, so we match on
    tuple + ordering rather than a small window around auth_success."""
    anchor_ts_str = session.get("earliest_event_ts")
    if anchor_ts_str is None:
        return None, None
    key = (session["src_ip"], session["src_port"])
    candidates = [c for c in tcp_connects_by_src.get(key, []) if c.get("dst_port") == SSH_PORT]
    anchor_ts = parse_ts(anchor_ts_str)

    best = None
    for c in candidates:  # sorted ascending
        c_ts = parse_ts(c["timestamp"])
        if c_ts <= anchor_ts:
            best = c  # keep overwriting; last one <= anchor wins
        else:
            break
    if best is None:
        return None, None
    delta = (anchor_ts - parse_ts(best["timestamp"])).total_seconds()
    return best, delta


def find_tcp_close_for_connect(tcp_connect_event: dict, closes_by_tuple: dict):
    """First tcp_close on the same 5-tuple occurring at/after the connect."""
    if tcp_connect_event is None:
        return None
    key = (tcp_connect_event["src_ip"], tcp_connect_event["dst_ip"],
           tcp_connect_event["src_port"], tcp_connect_event["dst_port"],
           tcp_connect_event["transport"])
    candidates = closes_by_tuple.get(key, [])
    connect_ts = parse_ts(tcp_connect_event["timestamp"])
    for c in candidates:
        if parse_ts(c["timestamp"]) >= connect_ts:
            return c
    return None

def index_process_exec_by_pid(events: list) -> dict:
    execs = [e for e in events if e["source"] == "process" and e["event_type"] == "process_exec"]
    index = {}
    for e in execs:
        pid = (e.get("process") or {}).get("pid")
        if pid is None:
            continue
        index.setdefault(pid, []).append(e)
    for pid in index:
        index[pid].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def find_process_context(tcp_event, process_index):
    """
    The process_exec that 'owns' this connection: the most recent exec
    for this pid at or before the connect timestamp. Same anchor logic
    as find_session_tcp_connect, applied to process lineage instead of
    SSH sessions.
    """
    pid = (tcp_event.get("process") or {}).get("pid")
    if pid is None:
        return None
    candidates = process_index.get(pid, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    best = None
    for e in candidates:  # sorted ascending
        if parse_ts(e["timestamp"]) <= tcp_ts:
            best = e
        else:
            break
    return best

def index_http_requests_by_tuple(http_requests: list) -> dict:
    """
    Same convention as TLS: key by the connection's own 5-tuple, since
    a request is sent client -> server, same direction as tcp_connect.
    """
    index = {}
    for req in http_requests:
        key = (req["src_ip"], req["dst_ip"], req["src_port"], req["dst_port"], req["transport"])
        index.setdefault(key, []).append(req)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def index_http_responses_by_tuple(http_responses: list) -> dict:
    """
    Responses travel server -> client, the reverse direction of the
    tcp_connect they belong to. Keyed on the response's own (src, dst)
    as observed on the wire; find_http_response_match swaps the
    tcp_event's tuple to look this index up.
    """
    index = {}
    for resp in http_responses:
        key = (resp["src_ip"], resp["dst_ip"], resp["src_port"], resp["dst_port"], resp["transport"])
        index.setdefault(key, []).append(resp)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def find_http_request_match(tcp_event, http_request_index):
    key = (tcp_event["src_ip"], tcp_event["dst_ip"], tcp_event["src_port"],
           tcp_event["dst_port"], tcp_event["transport"])
    candidates = http_request_index.get(key, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    best, best_delta = None, None
    for req in candidates:
        delta = (parse_ts(req["timestamp"]) - tcp_ts).total_seconds()
        if 0 <= delta <= HTTP_TIME_TOLERANCE_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = req, delta
    return best, best_delta


def find_http_response_match(tcp_event, http_response_index):
    """
    Look up the response index using the tcp_event's tuple reversed
    (server ip/port as src, client ip/port as dst) since that's how
    the response actually appears on the wire.
    """
    key = (tcp_event["dst_ip"], tcp_event["src_ip"], tcp_event["dst_port"],
           tcp_event["src_port"], tcp_event["transport"])
    candidates = http_response_index.get(key, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    best, best_delta = None, None
    for resp in candidates:
        delta = (parse_ts(resp["timestamp"]) - tcp_ts).total_seconds()
        if 0 <= delta <= HTTP_TIME_TOLERANCE_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = resp, delta
    return best, best_delta


def index_events_by_pid(events: list, source: str, event_types: set) -> dict:
    """Generic pid index for any (source, event_type) pair. Used for
    file_access and privilege (sudo_exec/capability_use) events."""
    index = {}
    for e in events:
        if e["source"] != source or e["event_type"] not in event_types:
            continue
        pid = (e.get("process") or {}).get("pid")
        if pid is None:
            continue
        index.setdefault(pid, []).append(e)
    for pid in index:
        index[pid].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def find_nearby_events(tcp_event, index, window_seconds):
    """
    All events for the same pid within +/- window_seconds of the
    connection. Bidirectional on purpose: privilege escalation or file
    writes can precede OR follow the connection depending on the
    attack pattern (stage-then-connect vs connect-then-persist).
    """
    pid = (tcp_event.get("process") or {}).get("pid")
    if pid is None:
        return []
    candidates = index.get(pid, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    matches = []
    for e in candidates:
        delta = abs((parse_ts(e["timestamp"]) - tcp_ts).total_seconds())
        if delta <= window_seconds:
            matches.append(e)
    return matches


def index_execve_by_pid(events: list) -> dict:
    execs = [e for e in events if e["source"] == "tetragon" and e["event_type"] == "sys_execve"]
    index = {}
    for e in execs:
        pid = (e.get("process") or {}).get("pid")
        if pid is None:
            continue
        index.setdefault(pid, []).append(e)
    for pid in index:
        index[pid].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def find_execve_for_session(session: dict, execs_by_pid: dict):
    pid = session.get("pid")
    anchor_ts_str = session.get("earliest_event_ts")
    if pid is None or anchor_ts_str is None:
        return None

    candidates = execs_by_pid.get(pid, [])
    if not candidates:
        return None

    anchor_ts = parse_ts(anchor_ts_str)
    best = None
    for event in candidates:  # sorted ascending
        event_ts = parse_ts(event["timestamp"])
        if event_ts <= anchor_ts:
            best = event
        else:
            break
    return best or candidates[0]


def correlate_ssh_sessions(events: list) -> list:
    sessions, orphans = build_ssh_sessions(events)
    if orphans:
        print(f"[correlator] {len(orphans)} ssh event(s) had no session_key "
              f"(e.g. pre-auth disconnects) and were excluded from sessions")

    tcp_connects = [e for e in events if e["source"] == "tetragon" and e["event_type"] == "tcp_connect"]
    tcp_closes = [e for e in events if e["source"] == "tetragon" and e["event_type"] == "tcp_close"]
    execs_by_pid = index_execve_by_pid(events)

    tcp_connects_by_src = {}
    for c in tcp_connects:
        key = (c["src_ip"], c["src_port"])
        tcp_connects_by_src.setdefault(key, []).append(c)
    for key in tcp_connects_by_src:
        tcp_connects_by_src[key].sort(key=lambda e: parse_ts(e["timestamp"]))

    closes_by_tuple = index_tcp_events_by_tuple(tcp_closes)

    results = []
    for session in sessions:
        tcp_connect_match, connect_delta = find_session_tcp_connect(session, tcp_connects_by_src)
        tcp_close_match = find_tcp_close_for_connect(tcp_connect_match, closes_by_tuple)
        execve_match = find_execve_for_session(session, execs_by_pid)
        connection_duration = None
        if tcp_connect_match and tcp_close_match:
            connection_duration = (
                parse_ts(tcp_close_match["timestamp"]) - parse_ts(tcp_connect_match["timestamp"])
            ).total_seconds()

        results.append({
            **session,
            "tcp_connect_matched": tcp_connect_match is not None,
            "tcp_connect_dst_ip": tcp_connect_match.get("dst_ip") if tcp_connect_match else None,
            "tcp_connect_process": tcp_connect_match.get("process") if tcp_connect_match else None,
            "tcp_connect_time_delta_ms": round(connect_delta * 1000) if connect_delta is not None else None,
            "tcp_close_matched": tcp_close_match is not None,
            "tcp_close_timestamp": tcp_close_match.get("timestamp") if tcp_close_match else None,
            "connection_duration_seconds": connection_duration,
            "execve_matched": execve_match is not None,
            "execve_binary": (execve_match.get("process") or {}).get("name") if execve_match else None,
            "execve_timestamp": execve_match.get("timestamp") if execve_match else None,
        })

    return results


def index_tcp_flows_by_tuple(tcp_flows: list) -> dict:
    index = {}
    for flow in tcp_flows:
        key = (flow["src_ip"], flow["dst_ip"], flow["src_port"], flow["dst_port"], flow["transport"])
        index.setdefault(key, []).append(flow)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["extra"]["start_ts"]))
    return index


def find_tcp_flow_match(tcp_event, tcp_flow_index):
    key = (tcp_event["src_ip"], tcp_event["dst_ip"], tcp_event["src_port"],
           tcp_event["dst_port"], tcp_event["transport"])
    candidates = tcp_flow_index.get(key, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])
    best, best_delta = None, None
    for flow in candidates:
        delta = abs((parse_ts(flow["extra"]["start_ts"]) - tcp_ts).total_seconds())
        if delta <= TCP_FLOW_TIME_TOLERANCE_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = flow, delta
    return best, best_delta

def main():
    events = load_events(INPUT_FILE)
    events.sort(key=lambda e: parse_ts(e["timestamp"]))

    enriched = correlate(events)
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        for e in enriched:
            f.write(json.dumps(e) + "\n")

    ssh_sessions = correlate_ssh_sessions(events)
    with SSH_SESSIONS_OUTPUT_FILE.open("w", encoding="utf-8") as f:
        for s in ssh_sessions:
            f.write(json.dumps(s) + "\n")

    with_dns = sum(1 for e in enriched if e["correlation"]["dns_matched"])
    with_tls = sum(1 for e in enriched if e["correlation"]["tls_matched"])
    with_ssh = sum(1 for e in enriched if e["correlation"]["ssh_matched"])
    with_tcp_flow = sum(1 for e in enriched if e["correlation"]["tcp_flow_matched"])
    sessions_with_tcp = sum(1 for s in ssh_sessions if s["tcp_connect_matched"])
    sessions_with_close = sum(1 for s in ssh_sessions if s["tcp_close_matched"])
    sessions_with_execve = sum(1 for s in ssh_sessions if s["execve_matched"])
    with_process_context = sum(1 for e in enriched if e["correlation"]["process_context_matched"])
    with_file_activity = sum(1 for e in enriched if e["correlation"]["file_activity_count"] > 0)
    with_privilege_activity = sum(1 for e in enriched if e["correlation"]["privilege_activity_count"] > 0)
    with_http = sum(1 for e in enriched if e["correlation"]["http_matched"])

    print(f"[correlator] {len(enriched)} tcp_connect events processed")
    print(f"[correlator] {with_dns} matched to a DNS response")
    print(f"[correlator] {with_tls} matched to a TLS ClientHello")
    print(f"[correlator] {with_ssh} matched to an SSH auth event")
    print(f"[correlator] {with_tcp_flow} matched to a TCP flow")
    print(f"[correlator] {with_http} matched to an HTTP request")
    print(f"[correlator] {with_process_context} matched to process context")
    print(f"[correlator] {with_file_activity} have nearby file activity")
    print(f"[correlator] {with_privilege_activity} have nearby privilege activity")
    print(f"[correlator] output -> {OUTPUT_FILE}")
    print(f"[correlator] {len(ssh_sessions)} ssh sessions built")
    print(f"[correlator] {sessions_with_tcp} sessions matched to a tcp_connect")
    print(f"[correlator] {sessions_with_close} sessions matched to a tcp_close")
    print(f"[correlator] {sessions_with_execve} sessions matched to a sys_execve")
    print(f"[correlator] output -> {SSH_SESSIONS_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
