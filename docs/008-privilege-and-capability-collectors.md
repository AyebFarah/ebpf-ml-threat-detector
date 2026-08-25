# Privilege and Capability Collectors — Design
## 1. Purpose

These two collectors detect privilege escalation and capability use around network
events — the P1 signal the project's collector priority framework lists as identifying
"suspicious escalation around network events" for post-compromise detection. Together
they distinguish a routine connection from one made immediately after a process gained
elevated privileges.

Two separate TracingPolicy files were used because `sudo`/`su`/`pkexec` invocation and
raw kernel capability checks have very different volume and reliability profiles, as
detailed below.

## 2. `sudo-exec.yaml` — Privileged Binary Invocation

Hooks `sys_execve` with a `matchBinaries` selector, the same proven pattern already used
by `ssh-sessions.yaml` for `sshd`/`ssh`/`ssh-agent`.

Because this reuses an execve/`matchBinaries` pattern already verified working
(`ssh-sessions.yaml`), no BTF signature check was required before deployment, the
kprobe's argument layout for a syscall entry point is stable across kernel versions in
a way that internal kernel functions are not.

## 3. `capability-change.yaml` — Kernel Capability Checks

Hooks `cap_capable`, the LSM function the kernel calls whenever it needs to check
whether a process holds a given capability.



## 4. Incident: Capability-Check Volume

The initial policy also matched `CAP_SYS_ADMIN (21)` and carried no rate limit. A test
run produced **6,738 events**, with **3,623 from a single process alias
(`/proc/self/exe`)** — almost entirely `CAP_SYS_ADMIN` checks. `cap_capable` fires on
nearly every kernel-level permission check; it is one of the hottest LSM hooks in the
kernel, and `CAP_SYS_ADMIN` in particular is checked constantly for routine, benign
reasons (namespace operations, mount checks) with no reliable way to separate benign
from suspicious checks at this layer.

### Fix — Two Layers

**Kernel-side:** `CAP_SYS_ADMIN` was dropped from the watched capability set (retaining
only `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_RESOURCE`, the capabilities most relevant
to this project's network-threat focus), and `rateLimit: "10s"` /
`rateLimitScope: "thread"` was added so repeated identical checks from the same thread
collapse into one exported event per 10-second window.

**Userspace-side (defense in depth):** the normalizer additionally aggregates
same-process/same-capability events within a rolling window, in case kernel-side rate
limiting alone is insufficient or unavailable on a given Tetragon build:


Each aggregated record carries `count`, `first_seen`, and `last_seen` in place of one
row per raw check, the same "many raw occurrences → one meaningful record" principle
already used by the TCP flow collector for packet aggregation.

### Verified Result

Post-fix, a comparable test run produced 20 aggregated capability-use events (down from
6,738 raw), with no loss of the underlying signal, repeated checks are represented as
a single record with an accurate count rather than being silently dropped.

## 5. Normalization

- `normalize_sudo_exec(raw)` → `event_type = "sudo_exec"`, `source = "privilege"`.
  Carries `arguments`, `uid`, `parent_binary` in `extra`.
- `normalize_capability_change(raw)` → per-raw-event normalization, feeding into
  `aggregate_capability_events()`, which is invoked as a dedicated post-processing step
  in the normalizer's `main()` (outside the generic per-line `NORMALIZERS` dispatch,
  since aggregation requires seeing all raw events for the source before collapsing
  them, the same reason DNS response-latency computation, documented separately, also
  runs as its own pass).

## 6. Design Principle Established

Any kprobe on a kernel function that isn't a syscall entry point requires a BTF
signature check before the policy is written, not after a failed deploy. Any kprobe on
a hot internal LSM/security hook (capability checks, permission checks) should default
to kernel-side rate limiting from the first deployment, with userspace aggregation as a
second line of defense rather than the primary control.