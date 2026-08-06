import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
COLLECTORS_DIR = REPO_ROOT / "observation" / "collectors"
PIPELINE_DIR = REPO_ROOT / "observation" / "pipeline"
MAIN_SCRIPT = REPO_ROOT / "main.py"
PYTHON = sys.executable


def run(cmd: list) -> int:
    result = subprocess.run(cmd)
    return result.returncode


def run_dns() -> int:
    return run([PYTHON, str(COLLECTORS_DIR / "dns_collector.py")])


def run_tls() -> int:
    return run([PYTHON, str(COLLECTORS_DIR / "tls_collector.py")])


def run_normalize() -> int:
    return run([PYTHON, str(PIPELINE_DIR / "normalizer.py")])


def run_correlate() -> int:
    return run([PYTHON, str(PIPELINE_DIR / "correlator.py")])


def run_all(no_postprocess: bool) -> int:
    cmd = [PYTHON, str(MAIN_SCRIPT)]
    if no_postprocess:
        cmd.append("--no-postprocess")
    return run(cmd)


def main():
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="eBPF-ML Threat Detector - proof of concept CLI",
    )
    parser.add_argument("command", choices=["dns", "tls", "normalize", "correlate", "all"])
    parser.add_argument(
        "--no-postprocess",
        action="store_true",
        help="(only applies to 'all') skip normalizer/correlator after stopping",
    )
    args = parser.parse_args()

    if args.command == "all":
        code = run_all(args.no_postprocess)
    else:
        dispatch = {
            "dns": run_dns,
            "tls": run_tls,
            "normalize": run_normalize,
            "correlate": run_correlate,
        }
        code = dispatch[args.command]()

    sys.exit(code)


if __name__ == "__main__":
    main()
