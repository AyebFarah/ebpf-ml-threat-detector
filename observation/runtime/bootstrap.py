import os
import shutil
import subprocess
import sys
from .. import paths
from ..pipeline.normalizer import main as run_normalizer
from ..pipeline.correlator import main as run_correlator
from ..database.loader import load_into_database

PYTHON = sys.executable

CRITICAL_PROCESSES = {
    "dns_collector",
    "tls_collector",
    "ssh_collector",
    "tcp_collector",
    "http_collector",
    "dispatcher",
}


def create_required_directories():
    for d in paths.REQUIRED_DIRS:
        d.mkdir(parents=True, exist_ok=True)
        print(f"[main] ensured directory: {d}")


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
    commands = {
        "dns_collector": [PYTHON, "-u", "-m", "observation.collectors.dns_collector"],
        "tls_collector": [PYTHON, "-u", "-m", "observation.collectors.tls_collector"],
        "ssh_collector": [PYTHON, "-u", "-m", "observation.collectors.ssh_collector"],
        "tcp_collector": [PYTHON, "-u", "-m", "observation.collectors.tcp_collector"],
        "http_collector": [PYTHON, "-u", "-m", "observation.collectors.http_collector"],
    }
    if tetra_available:
        commands["dispatcher"] = [
            "bash", "-c",
            f"tetra getevents -o json | {PYTHON} -u -m observation.pipeline.dispatcher",
        ]
    return commands

def run_post_processing(scenario: str, label: str = "benign",
                        notes: str | None = None,
                        duration_seconds: int | None = None) -> int:
    print("[main] running normalizer...")
    run_normalizer()
    print("[main] running correlator...")
    run_correlator()
    print("[main] loading into database...")
    return load_into_database(scenario=scenario, label=label, notes=notes,
                              duration_seconds=duration_seconds)

def reset_event_log_files():
    policy_files = [
        paths.TCP_CONNECT_POLICY_FILE,
        paths.DNS_QUERIES_POLICY_FILE,
        paths.DOT_QUERIES_POLICY_FILE,
        paths.SSH_SESSIONS_POLICY_FILE,
        paths.LISTENING_PORTS_POLICY_FILE,
        paths.PROCESS_EXEC_POLICY_FILE,
        paths.PROCESS_EXIT_POLICY_FILE,
        paths.SENSITIVE_FILE_ACCESS_POLICY_FILE,
        paths.SUDO_EXEC_POLICY_FILE,
        paths.CAPABILITY_CHANGE_POLICY_FILE,
    ]

    for path in policy_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    print("[main] reset Tetragon event logs.")
