FEATURE_VERSION = "v2"
AGGREGATION_VERSION = "sliding_15s_5s_v1"

WINDOW_SECONDS = 15
STRIDE_SECONDS = 5

WELL_KNOWN_PORT_MAX = 1024
HIGH_PORT_MIN = 49152

RARE_JA4_THRESHOLD = 3  # seen fewer than N times in the benign baseline => "rare"

SENSITIVE_TIER1_PREFIXES = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d/",
    "/etc/ssh/", "/root/.ssh/", "/var/run/secrets/", "/run/secrets/",
    "/etc/cron.", "/var/spool/cron/", "/etc/systemd/system/",
    "/usr/lib/systemd/system/", "/etc/ld.so.preload",
]

SHELL_BINARIES = {"bash", "sh", "zsh", "dash", "ash", "csh", "tcsh", "ksh"}
INTERPRETER_BINARIES = {"python", "python3", "perl", "ruby", "node", "php", "lua"}

PRIVILEGE_EVENT_TYPES = {"sudo_exec", "capability_use"}