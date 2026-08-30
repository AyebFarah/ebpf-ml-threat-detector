import argparse
import sys
from observation.orchestrator import run

def parse_args():
    parser = argparse.ArgumentParser(
        description="eBPF Network Observation PoC"
    )
    parser.add_argument(
        "--no-postprocess",
        action="store_true",
        help="Do not run normalizer/correlator automatically when stopped.",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Label for this collection run, e.g. browser_light, ide_development, "
             "ssh_admin. Required for real dataset runs; if omitted you'll be "
             "prompted before post-processing.",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="benign",
        help="ML target class for this run: 'benign' or 'attack:<type>'.",
    )
    parser.add_argument(
        "--notes",
        type=str,
        default=None,
        help="Freeform notes about this run (environment, anomalies, etc).",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    print("======================================")
    print("     eBPF Network Observation PoC")
    print("======================================")
    return run(
        post_process=not args.no_postprocess,
        scenario=args.scenario,
        label=args.label,
        notes=args.notes,
    )
if __name__ == "__main__":
    sys.exit(main())