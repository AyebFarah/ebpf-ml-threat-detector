# SSH Observation and Correlation

## 1. Purpose

The SSH component of the observation layer is responsible for detecting and reconstructing SSH connection activity, with particular focus on authentication behavior.

The goal is not only to detect successful SSH sessions, but also to retain failed authentication attempts, since repeated failures can be an important security signal for the future machine-learning layer.

The SSH pipeline is:

```text
SSH logs
   │
   ▼
ssh-collector.py
   │
   ▼
SSH normalized events
   │
   ▼
correlator.py
   │
   ├── TCP connection
   ├── TCP close
   └── sshd execve
   │
   ▼
correlated_events.jsonl
```

## 2. SSH Collector

The SSH collector is located at:

```text
observation/collectors/ssh-collector.py
```

It reads SSH activity from:

```bash
journalctl -u ssh
```

and falls back to:

```text
/var/log/auth.log
```

if the journal source is unavailable.

The collector parses SSH-related log messages and converts them into structured events.

## 3. SSH Events Collected

The collector currently recognizes the following event types:

| Event | Meaning |
|---|---|
| `ssh_auth_success` | User successfully authenticated |
| `ssh_auth_failure` | Authentication attempt failed |
| `ssh_invalid_user` | Authentication involved an invalid or nonexistent user |
| `ssh_session_opened` | PAM opened an authenticated session |
| `ssh_session_closed` | PAM closed an authenticated session |
| `ssh_disconnected` | SSH connection was disconnected or closed |

For example, a failed authentication can produce:

```json
{
  "event_type": "ssh_auth_failure",
  "username": "pharah",
  "src_ip": "*.*.*.*",
  "src_port": 36656,
  "dst_port": 22,
  "auth_method": "password",
  "result": "failure"
}
```

## 4. SSH Session Key

SSH authentication messages need to be grouped together into the same connection.

The collector therefore creates a `session_key`:

```text
src_ip:src_port:username
```

Example:

```text
127.0.0.1:36656:pharah
```

This allows multiple authentication events belonging to the same SSH connection to be grouped.

For example:

- `ssh_auth_failure`
- `ssh_auth_failure`
- `ssh_auth_success`
- `ssh_session_opened`

can be treated as one SSH session.

## 5. Failed Authentication Attempts

Failed authentication attempts are not discarded.

This is important because a failed SSH connection can itself represent suspicious behavior.

For example:

- Attempt 1 → failure
- Attempt 2 → failure
- Attempt 3 → failure
- Connection → disconnected

is potentially more useful for threat detection than simply recording that “no SSH session was created.”

The resulting correlated event can contain:

```json
{
  "ssh": {
    "auth_attempts": 2,
    "auth_failures": 2,
    "auth_success": false,
    "disconnected": true
  }
}
```

Therefore, the absence of a successful session does not mean the SSH activity is ignored.

## 6. Unknown User Information

Some SSH events occur before authentication has provided enough information to identify a user.

In these cases, the username may be unavailable.

The design principle is:

- missing information → `UNKNOWN` / `null`

rather than:

- missing information → discard event

This prevents pre-authentication activity from being lost.

## 7. SSH Session Aggregation

The correlator groups SSH events into session-level information.

For example, a failed SSH attempt can become:

```json
{
  "session_key": "**.**.**.**:36656:pharah",
  "username": "pharah",
  "event_types_seen": [
    "ssh_auth_failure",
    "ssh_auth_failure",
    "ssh_disconnected"
  ],
  "auth_success_ts": null,
  "session_opened_ts": null,
  "disconnected_ts": "..."
}
```

A successful authentication can contain:

```json
{
  "session_key": "**.**.**.**:47310:pharah",
  "username": "pharah",
  "event_types_seen": [
    "ssh_auth_failure",
    "ssh_auth_success",
    "ssh_session_opened"
  ],
  "auth_success_ts": "...",
  "auth_method": "password",
  "session_opened_ts": "..."
}
```

## 8. Correlation With Tetragon

SSH logs and Tetragon provide complementary information.

**SSH collector provides:**

- username
- authentication result
- authentication method
- authentication attempts
- session information

**Tetragon provides:**

- TCP connection
- source and destination IP
- source and destination port
- SSH process
- TCP close
- `sshd` execve

The correlator combines these sources.

For example:

```text
SSH authentication
       │
       │ src_ip + src_port + SSH session
       ▼
Tetragon tcp_connect
       │
       ├── destination IP
       ├── process
       └── connection information
```

This produces a richer SSH observation.

## 9. TCP Correlation

An SSH session can be associated with a Tetragon `tcp_connect`.

The resulting record may contain:

```json
{
  "tcp_connect_matched": true,
  "tcp_connect_dst_ip": "**.**.**.**",
  "tcp_connect_process": {
    "pid": 15735,
    "name": "/usr/bin/ssh"
  }
}
```

This establishes a relationship between:

- SSH authentication activity
- network connection

## 10. TCP Close Correlation

If a corresponding `tcp_close` is available, the correlator also records connection termination.

Example:

```json
{
  "tcp_close_matched": true,
  "tcp_close_timestamp": "...",
  "connection_duration_seconds": 5.886655
}
```

This is useful because connection duration can become an ML feature later.

## 11. sshd Process Correlation

The correlator can also associate the SSH session with the corresponding `sshd` execution event.

Example:

```json
{
  "execve_matched": true,
  "execve_binary": "/usr/sbin/sshd",
  "execve_timestamp": "..."
}
```

This provides additional process-level context for the SSH connection.

## 12. ssh_sessions.jsonl

The SSH correlator currently produces:

```text
samples/unified_events/ssh_sessions.jsonl
```

This file is an SSH-specific intermediate representation.

It is useful for:

- debugging SSH correlation
- validating session reconstruction
- inspecting authentication sequences
- verifying TCP/SSH matching

It is not intended to be the main ML dataset.

## 13. Final SSH Output

The SSH information is incorporated into:

```text
samples/unified_events/correlated_events.jsonl
```

For example:

```json
{
  "network": {
    "src_ip": "**.**.**.**",
    "dst_ip": "**.**.**.**",
    "src_port": 47298,
    "dst_port": 22,
    "transport": "tcp"
  },
  "ssh": {
    "session_key": "**.**.**.**:47298:pharah",
    "username": "pharah",
    "auth_attempts": 2,
    "auth_failures": 2,
    "auth_success": false,
    "auth_method": null,
    "session_opened": false,
    "disconnected": true
  }
}
```

This is the representation that will eventually be transformed into ML features.

## 14. Why This Design?

The SSH implementation deliberately separates three responsibilities:

```text
ssh-collector.py
        │
        │ Detect and parse SSH events
        ▼
normalizer.py
        │
        │ Convert to common event format
        ▼
correlator.py
        │
        │ Reconstruct SSH activity + network context
        ▼
correlated_events.jsonl
```

- The collector does not perform ML analysis.
- The correlator does not perform ML analysis.

They produce reliable structured observations that can later be transformed into ML features.

## 15. Validated Scenarios

The SSH pipeline has been tested with both:

### Failed authentication

Example result:

- `auth_attempts = 2`
- `auth_failures = 2`
- `auth_success = false`
- `disconnected = true`

### Successful authentication

Example result:

- `auth_attempts = 1`
- `auth_failures = 0`
- `auth_success = true`
- `auth_method = password`
- `session_opened = true`

This confirms that the SSH component distinguishes successful and unsuccessful authentication behavior while retaining the associated network and process information.

## 16. Role in Threat Detection

The SSH component provides several potentially useful ML features:

- `auth_attempts`
- `auth_failures`
- `auth_success`
- `auth_method`
- `session_opened`
- `session_closed`
- `session_duration`
- `connection_duration`
- `tcp_connect_matched`
- `tcp_close_matched`
- `execve_matched`

These features can later help distinguish normal SSH activity from suspicious behavior such as:

- multiple authentication failures → possible brute-force behavior
- failed authentication → successful authentication → long-lived session

The SSH component therefore acts as an observation and correlation layer, while the actual threat classification will be performed later by the ML layer.
