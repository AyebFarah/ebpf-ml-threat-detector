# Sensitive File Access Collector — Design

## 1. Purpose

The file activity collector connects network activity to sensitive filesystem
operations (e.g: credential reads, persistence-path writes, temp-directory executable
drops..) that TCP/DNS/TLS telemetry alone cannot see. This collector turns a bare network connection into a
narrative such as "process read `~/.ssh/authorized_keys`, then made an outbound
connection."

## 2. TracingPolicy

`observation/policies/sensitive-file-access.yaml` hooks `security_file_permission`, the
LSM check the kernel calls on every file access, and filters in-kernel to a path
allowlist so only policy-selected paths are exported to userspace.


## 3. Path Selection — Three Tiers

The final policy groups watched paths into three selector blocks within the same
`TracingPolicy`, each with different volume characteristics and matching rules:

### Tier 1 — Credential and persistence paths (always low volume)

```text
/etc/shadow, /etc/passwd, /etc/sudoers, /etc/sudoers.d/, /etc/ssh/,
/root/.ssh/, /home/<user>/.ssh/, /var/run/secrets/, /run/secrets/,
/etc/cron.*, /var/spool/cron/, /etc/systemd/system/,
/usr/lib/systemd/system/, /etc/ld.so.preload
```

No rate limiting is needed here — legitimate processes rarely touch these paths, so raw
volume stays naturally low (single digits to low tens of events per session).

### Tier 2 — `/dev/shm/` and `/var/tmp/`

Watched for both reads and writes, no rate limiting. Lower legitimate traffic than
`/tmp/` on a typical desktop.

### Tier 3 — `/tmp/`

Restricted to **writes only** (`mask == MAY_WRITE`) with a kernel-side rate limit:

Dropping read events and rate-limiting writes per-thread was necessary because `/tmp/`
sees continuous legitimate churn from browsers, IDEs, and package managers.

## 4. Incident 1: Uncontrolled Volume from a Broad `/home/` Prefix

An early version of the policy included a bare `/home/` prefix (intended to catch SSH
key access broadly). In a 2-minute capture window this alone produced **287,092 raw
events out of 287,115 total** — a 99.99% share.

The bare `/home/` prefix was catching every cache write from IntelliJ, Brave, and the
JetBrains embeddings server — none of it security-relevant. This mirrored an earlier
noise incident with the `cap_capable` capability collector, and confirmed the same
underlying lesson: any kprobe path/argument filter broad enough to catch a whole
top-level directory under active user processes will flood, regardless of how narrow
the *intent* was.

### Fix

- Removed the bare `/home/` prefix entirely.
- Replaced it with the specific `/home/<user>/.ssh/` path actually needed.
- Retained `/tmp/`, `/var/tmp/`, `/dev/shm/` but applied the tiered
  read/write-restriction and rate-limiting scheme described in Section 3.


A reduction from 287,115 to 16 events for an equivalent capture window, with zero loss
of coverage on the credential/persistence paths that matter.

## 5. Incident 2: `/dev/shm` Flood from Browser Activity

After the Tier-1/Tier-2/Tier-3 split in Section 3 was deployed, `/tmp/` and `/home/`
were confirmed fixed — but a subsequent, heavier capture session surfaced a second,
distinct flood source: `/dev/shm`.

### Fix

`/dev/shm` was moved out of Tier 2 and into the same write-only + rate-limited
selector block as `/tmp/`, on the reasoning that the dominant share of `/dev/shm`
traffic is almost certainly read-side shared-memory-segment access checks, not writes.

`/var/tmp/` remained in its own, unrestricted Tier 2 block, since it stayed low-volume
across both test sessions and had not shown any sign of the same growth pattern.

A comparably heavy browsing session, re-captured after the fix, produced:

```text
sensitive-file-access.jsonl: 5 total events
```

Down from 2,098 for a session of similar length and activity profile.


## 6. Design Principle Established

This incident produced a reusable rule for every future path-based or high-frequency
kprobe policy in this project: **never filter on a bare top-level directory an active
user process tree lives under** (`/home/`, `/root/` without a specific subpath). Always
prefer the most specific literal path that still covers the intended signal, and treat
any directory known for legitimate scratch-space use (`/tmp`, `/var/tmp`, `/dev/shm`,
caches) as requiring write-only + rate-limited treatment by default, not as an
exception to add later.