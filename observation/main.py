import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
OBSERVATION_DIR = REPO_ROOT / "observation"
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
    PIPELINE_DIR / "dispatcher.py",
    PIPELINE_DIR / "normalizer.py",
    PIPELINE_DIR / "correlator.py",
]

CRITICAL_PROCESSES = {"dns_collector", "tls_collector", "dispatcher"}
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


def verify_dependencies():
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

    fatal = (os.geteuid() != 0) or ("scapy is not installed (pip install scapy)." in problems)
    if fatal:
        sys.exit(1)

    return tetra_available

class ProcessSupervisor:
    def __init__(self):
        self.processes = {}

    def start(self, name: str, cmd: list):
        print(f"[main] starting {name}: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        self.processes[name] = proc

    def any_alive(self) -> bool:
        return any(p.poll() is None for p in self.processes.values())

    def poll_for_crashes(self):
        crashed = [
            (name, proc.returncode)
            for name, proc in self.processes.items()
            if proc.poll() is not None
        ]
        for name, _ in crashed:
            del self.processes[name]
        return crashed

    def stop_all(self, timeout: int = 5):
        for name, proc in self.processes.items():
            if proc.poll() is None:
                print(f"[main] stopping {name} (pid={proc.pid})")
                proc.send_signal(signal.SIGINT)

        deadline = time.time() + timeout
        for name, proc in self.processes.items():
            remaining = max(0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                print(f"[main] {name} did not stop in time, killing")
                proc.kill()
                proc.wait()

def build_commands(tetra_available: bool) -> dict:
    commands = {
        "dns_collector": [PYTHON, str(COLLECTORS_DIR / "dns_collector.py")],
        "tls_collector": [PYTHON, str(COLLECTORS_DIR / "tls_collector.py")],
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


def main(post_process: bool = True):
    create_required_directories()
    verify_required_scripts()
    tetra_available = verify_dependencies()

    supervisor = ProcessSupervisor()
    for name, cmd in build_commands(tetra_available).items():
        supervisor.start(name, cmd)

    print("[main] pipeline running. Press Ctrl+C to stop.")

    critical_crash = False

    try:
        while supervisor.any_alive():
            for name, code in supervisor.poll_for_crashes():
                print(f"[main] WARNING: {name} exited unexpectedly (code={code})")
                if name in CRITICAL_PROCESSES:
                    print(
                        f"[main] {name} is a critical process — "
                        f"stopping the rest of the pipeline to avoid "
                        f"collecting incomplete data."
                    )
                    critical_crash = True
                    break
            if critical_crash:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[main] Ctrl+C received, stopping pipeline...")
    finally:
        supervisor.stop_all()
        print("[main] all collectors stopped.")

        if post_process:
            run_post_processing()

    if critical_crash:
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the full observation pipeline.")
    parser.add_argument(
        "--no-postprocess",
        action="store_true",
        help="don't run normalizer/correlator automatically on stop",
    )
    args = parser.parse_args()
    main(post_process=not args.no_postprocess)
