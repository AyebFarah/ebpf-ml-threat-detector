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
    return parser.parse_args()
def main():
    args = parse_args()
    print("======================================")
    print("     eBPF Network Observation PoC")
    print("======================================")
    return run(
        post_process=not args.no_postprocess
    )
if __name__ == "__main__":
    sys.exit(main())