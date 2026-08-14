import argparse
import sys
import time

from runtime import bootstrap
from runtime.supervisor import ProcessSupervisor


def run(post_process: bool = True) -> int:
    bootstrap.create_required_directories()
    bootstrap.verify_required_scripts()
    bootstrap.reset_event_log_files()
    tetra_available = bootstrap.verify_dependencies()

    supervisor = ProcessSupervisor()
    for name, cmd in bootstrap.build_commands(tetra_available).items():
        supervisor.start(name, cmd)

    print("[main] pipeline running. Press Ctrl+C to stop.")

    critical_crash = False
    try:
        while supervisor.any_alive():
            for name, code in supervisor.poll_for_crashes():
                print(f"[main] WARNING: {name} exited unexpectedly (code={code})")
                if name in bootstrap.CRITICAL_PROCESSES:
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
            bootstrap.run_post_processing()

    return 1 if critical_crash else 0


def parse_args():
    parser = argparse.ArgumentParser(description="Run the full observation pipeline.")
    parser.add_argument(
        "--no-postprocess",
        action="store_true",
        help="don't run normalizer/correlator automatically on stop",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(run(post_process=not args.no_postprocess))
