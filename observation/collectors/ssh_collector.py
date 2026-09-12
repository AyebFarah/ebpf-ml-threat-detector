import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from observation import paths
from pathlib import Path

OUTPUT_FILE = paths.SSH_EVENTS_FILE

def ensure_output_dir():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

AUTH_LOG_PATH = Path("/var/log/auth.log")
SSH_PORT = 22

RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_FAILED_INVALID = re.compile(
    r"Failed (?P<method>\S+) for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SESSION_OPENED = re.compile(
    r"pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)"
)
RE_SESSION_CLOSED = re.compile(
    r"pam_unix\(sshd:session\): session closed for user (?P<user>\S+)"
)
RE_DISCONNECTED = re.compile(
    r"Disconnected from (?:authenticating user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)"
)
RE_CONN_CLOSED_PREAUTH = re.compile(
    r"Connection closed by (?:authenticating user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)"
)


_open_sessions = {}

def stop_process(proc):
    if proc is None:
        return

    if proc.poll() is not None:
        return

    proc.terminate()

    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

def write_event(event: dict) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")


def session_key(src_ip, src_port, username):
    """
    Canonical SSH session identity: the client's (src_ip, src_port) plus
    the authenticated username. This is the single definition used by
    both ssh-collector.py (to tag events as they're collected) and
    correlator.py (to re-join those events into sessions later).
    """
    if src_ip is None or src_port is None or username is None:
        return None
    return f"{src_ip}:{src_port}:{username}"


def _base_event(timestamp: str, event_type: str, pid, src_ip=None, src_port=None,
                 username=None) -> dict:

    session_username = username if username is not None else "UNKNOWN"
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "src_ip": src_ip,
        # Intentionally left None. This collector has no visibility into
        # which local address sshd accepted the connection on — auth.log
        # / journalctl never carry it. Tetragon's port-22 kprobe events
        # do carry it, so dst_ip is filled in at correlation time instead
        # of being guessed or hardcoded here. Same reasoning applies to
        # pid provenance: this pid comes straight from auth.log and is
        # not independently verified — the correlator cross-checks it
        # against Tetragon's sys_execve for ground truth.
        "dst_ip": None,
        "src_port": src_port,
        "dst_port": SSH_PORT,
        "transport": "tcp",
        "direction": "inbound",
        "pid": pid,
        "session_key": session_key(src_ip, src_port, session_username),
    }


def parse_line(message: str, timestamp: str, pid) -> dict | None:
    """Parse one sshd log message into an event dict, or None if it's not
    one of the message types we care about."""
    m = RE_ACCEPTED.search(message)
    if m:
        src_ip, src_port, user = m["ip"], int(m["port"]), m["user"]
        event = _base_event(timestamp, "ssh_auth_success", pid, src_ip, src_port, user)
        event.update(username=user, auth_method=m["method"], result="success")

        if pid in _open_sessions:
            print(
                f"[SSH] WARNING: pid={pid} had an open, un-torn-down session "
                f"context ({_open_sessions[pid].get('username')}) when a new "
                f"'Accepted' line arrived for {user}. Overwriting — the OS "
                f"reused this pid before we saw a disconnect/close for the "
                f"previous session.",
                file=sys.stderr,
            )

        _open_sessions[pid] = {
            "src_ip": src_ip, "src_port": src_port,
            "username": user, "start": timestamp,
        }
        return event

    m = RE_FAILED_INVALID.search(message)
    if m:
        event = _base_event(timestamp, "ssh_auth_failure", pid, m["ip"], int(m["port"]), m["user"])
        event.update(username=m["user"], auth_method=m["method"], result="failure",
                      invalid_user=True)
        return event

    m = RE_FAILED.search(message)
    if m:
        event = _base_event(timestamp, "ssh_auth_failure", pid, m["ip"], int(m["port"]), m["user"])
        event.update(username=m["user"], auth_method=m["method"], result="failure",
                      invalid_user=False)
        return event

    m = RE_INVALID_USER.match(message)
    if m:
        event = _base_event(timestamp, "ssh_invalid_user", pid, m["ip"], int(m["port"]), m["user"])
        event.update(username=m["user"], auth_method=None, result="failure",
                      invalid_user=True)
        return event

    m = RE_SESSION_OPENED.search(message)
    if m:
        ctx = _open_sessions.get(pid)
        if ctx is not None and ctx.get("username") != m["user"]:
            print(
                f"[SSH] WARNING: pid={pid} session-opened for user={m['user']} "
                f"but the tracked context was for user={ctx.get('username')}. "
                f"Discarding stale context to avoid cross-user attribution.",
                file=sys.stderr,
            )
            ctx = None

        event = _base_event(
            timestamp, "ssh_session_opened", pid,
            ctx.get("src_ip") if ctx else None,
            ctx.get("src_port") if ctx else None,
            m["user"],
        )
        event.update(username=m["user"])
        return event

    m = RE_SESSION_CLOSED.search(message)
    if m:
        ctx = _open_sessions.get(pid)
        if ctx is not None and ctx.get("username") != m["user"]:
            print(
                f"[SSH] WARNING: pid={pid} session-closed for user={m['user']} "
                f"but the tracked context was for user={ctx.get('username')}. "
                f"Discarding stale context; duration will be unavailable.",
                file=sys.stderr,
            )
            ctx = None
        else:
            # Only pop when it's actually this session's context — popping
            # unconditionally on pid match alone would let mismatched
            # contexts get silently consumed.
            _open_sessions.pop(pid, None)

        duration = None
        if ctx and ctx.get("start"):
            try:
                start = datetime.fromisoformat(ctx["start"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                duration = (end - start).total_seconds()
            except ValueError:
                pass

        event = _base_event(
            timestamp, "ssh_session_closed", pid,
            ctx.get("src_ip") if ctx else None,
            ctx.get("src_port") if ctx else None,
            m["user"],
        )
        event.update(username=m["user"], session_duration_seconds=duration)
        return event

    m = RE_DISCONNECTED.search(message) or RE_CONN_CLOSED_PREAUTH.search(message)
    if m:
        ctx = _open_sessions.get(pid)
        user = m.groupdict().get("user")
        if ctx is not None and user is not None and ctx.get("username") != user:
            pass
        else:
            _open_sessions.pop(pid, None)

        event = _base_event(timestamp, "ssh_disconnected", pid, m["ip"], int(m["port"]), user)
        event.update(username=user)
        return event

    return None


def handle_event(message: str, timestamp: str, pid, verbose=True) -> None:
    event = parse_line(message, timestamp, pid)
    if event is None:
        return
    write_event(event)
    if verbose:
        detail = event.get("username") or event.get("src_ip") or ""
        print(f"[SSH {event['event_type']}] {detail} "
              f"({event.get('src_ip')}:{event.get('src_port')}) pid={pid}")


def run_journalctl():
    """Yield (message, timestamp_iso, pid) tuples from `journalctl -u ssh -f -o json`."""
    proc = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-o", "json", "-n", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = entry.get("MESSAGE")
            if not isinstance(message, str):
                continue
            usec = entry.get("__REALTIME_TIMESTAMP")
            if usec is None:
                continue
            ts = datetime.fromtimestamp(int(usec) / 1_000_000, tz=timezone.utc).isoformat()
            pid = entry.get("_PID", entry.get("SYSLOG_PID"))
            if pid is not None:
                pid = int(pid)
            yield message, ts, pid
    finally:
        stop_process(proc)


RE_AUTHLOG_PREFIX = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) \S+ "
    r"sshd\[(?P<pid>\d+)\]:\s*(?P<msg>.*)$"
)


def run_auth_log_tail():
    """Yield (message, timestamp_iso, pid) tuples by tailing auth.log.
    Second-resolution only; year is inferred as the current year."""
    proc = subprocess.Popen(
        ["tail", "-F", "-n", "0", str(AUTH_LOG_PATH)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    year = datetime.now(timezone.utc).year
    try:
        for line in proc.stdout:
            m = RE_AUTHLOG_PREFIX.match(line.rstrip("\n"))
            if not m:
                continue
            try:
                ts = datetime.strptime(
                    f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
                ).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
            yield m["msg"], ts, int(m["pid"])
    finally:
        stop_process(proc)


def main():
    print("Starting SSH collector...")
    reset_output_file()

    source = run_journalctl
    source_name = "journalctl -u ssh"
    probe = subprocess.run(
        ["journalctl", "-u", "ssh", "-n", "1", "-o", "json"],
        capture_output=True, text=True,
    )
    if probe.returncode != 0 or not probe.stdout.strip():
        if AUTH_LOG_PATH.exists():
            source = run_auth_log_tail
            source_name = str(AUTH_LOG_PATH)
        else:
            print(
                "[SSH] ERROR: neither `journalctl -u ssh` nor "
                f"{AUTH_LOG_PATH} produced usable output. "
                "SSH collector cannot start.",
                file=sys.stderr,
            )
            sys.exit(1)
    print(f"[SSH] reading from: {source_name}")

    try:
        for message, ts, pid in source():
            handle_event(message, ts, pid)
    except KeyboardInterrupt:
        print("\n[SSH] Collector stopped.")


if __name__ == "__main__":
    main()
