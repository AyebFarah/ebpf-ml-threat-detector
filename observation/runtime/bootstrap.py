import os
import shutil
import subprocess
import sys
from pathlib import Path

OBSERVATION_DIR = Path(__file__).resolve().parent.parent

COLLECTORS_DIR = OBSERVATION_DIR / "collectors"
PIPELINE_DIR = OBSERVATION_DIR / "pipeline"
SAMPLES_DIR = OBSERVATION_DIR / "samples"

REQUIRED_DIRS = [
    SAMPLES_DIR / "collectors_events",
    SAMPLES_DIR / "event_logs_by_policy",
    SAMPLES_DIR / "unified_events",
    SAMPLES_DIR / "raw_event_logs",
]

REQUIRED_SCRIPTS = [
    COLLECTORS_DIR / "dns_collector.py",
    COLLECTORS_DIR / "tls_collector.py",
    COLLECTORS_DIR / "ssh_collector.py",
    COLLECTORS_DIR / "tcp_collector.py",
    PIPELINE_DIR / "dispatcher.py",
    PIPELINE_DIR / "normalizer.py",
    PIPELINE_DIR / "correlator.py",
]

# ssh_collector is deliberately NOT critical: it enriches auth context but
# the rest of the pipeline (network visibility via DNS/TLS/Tetragon) is
# still fully valid without it. dns_collector/tls_collector/dispatcher stay
# critical because losing any of them means incomplete network capture.
CRITICAL_PROCESSES = {"dns_collector", "tls_collector", "ssh_collector", "tcp_collector", "dispatcher"}
PYTHON = sys.executable


def create_required_directories():
    for d in REQUIRED_DIRS:
        d.mkdir(parents=True, exist_ok=True)
        print(f"[main] ensured directory: {d}")


def verify_required_scripts():
    missing = [str(s) for s in REQUIRED_SCRIPTS if not s.is_file()]
    if missing:
        print("[main] FATAL: required script(s) missing:")
        for m in missing:
            print(f"  - {m}")
        sys.exit(1)
    print("[main] all required scripts present.")


def verify_dependencies() -> bool:
    """
    Check root privileges, scapy availability, and whether the 'tetra'
    binary is on PATH. Exits the process on fatal problems (not root,
    or scapy missing). Returns whether tetra is available — its
    absence is non-fatal, since the DNS/TLS collectors don't need it.
    """
    problems = []

    if os.geteuid() != 0:
        problems.append(
            "Not running as root. DNS/TLS collectors use raw packet "
            "capture and need root privileges (run with sudo)."
        )

    try:
        import scapy  # noqa: F401
    except ImportError:
        problems.append("scapy is not installed (pip install scapy).")

    tetra_available = shutil.which("tetra") is not None
    if not tetra_available:
        problems.append(
            "'tetra' binary not found in PATH. Tetragon capture will "
            "be skipped; DNS/TLS collectors will still run."
        )

    if problems:
        print("[main] dependency check:")
        for p in problems:
            print(f"  - {p}")

    fatal = (os.geteuid() != 0) or (
        "scapy is not installed (pip install scapy)." in problems
    )
    if fatal:
        sys.exit(1)

    return tetra_available


def build_commands(tetra_available: bool) -> dict:
    """Build the {name: argv} map of subprocess commands to launch."""
    commands = {
        "dns_collector": [PYTHON, str(COLLECTORS_DIR / "dns_collector.py")],
        "tls_collector": [PYTHON, str(COLLECTORS_DIR / "tls_collector.py")],
        "ssh_collector": [PYTHON, str(COLLECTORS_DIR / "ssh_collector.py")],
        "ssh_collector": [PYTHON, str(COLLECTORS_DIR / "tcp_collector.py")],

    }

    if tetra_available:
        commands["dispatcher"] = [
            "bash", "-c",
            f"tetra getevents -o json | {PYTHON} {PIPELINE_DIR / 'dispatcher.py'}",
        ]

    return commands


def run_post_processing():
    print("[main] running normalizer...")
    subprocess.run([PYTHON, str(PIPELINE_DIR / "normalizer.py")], check=False)
    print("[main] running correlator...")
    subprocess.run([PYTHON, str(PIPELINE_DIR / "correlator.py")], check=False)

def reset_event_log_files():
    policy_files = [
        "tcp-connect.jsonl",
        "dns-queries.jsonl",
        "dot-queries.jsonl",
        "ssh-sessions.jsonl",
        "listening-ports.jsonl",
        "process-lifecycle.jsonl",
        "_unmapped.jsonl",
    ]

    event_dir = SAMPLES_DIR / "event_logs_by_policy"

    for filename in policy_files:
        path = event_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    print("[main] reset Tetragon event logs.")
