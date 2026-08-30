import time
from observation.runtime import bootstrap
from observation.runtime.supervisor import ProcessSupervisor

def run(post_process: bool = True, scenario: str | None = None,
        label: str = "benign", notes: str | None = None) -> int:
    bootstrap.create_required_directories()
    bootstrap.reset_event_log_files()
    tetra_available = bootstrap.verify_dependencies()
    supervisor = ProcessSupervisor()
    for name, cmd in bootstrap.build_commands(tetra_available).items():
        supervisor.start(name, cmd)
    print("[orchestrator] pipeline running. Press Ctrl+C to stop.")
    critical_crash = False
    start_ts = time.time()
    try:
        while supervisor.any_alive():
            for name, code in supervisor.poll_for_crashes():
                print(
                    f"[orchestrator] WARNING: "
                    f"{name} exited unexpectedly (code={code})"
                )
                if name in bootstrap.CRITICAL_PROCESSES:
                    print(
                        f"[orchestrator] {name} is a critical process — "
                        f"stopping the rest of the pipeline."
                    )
                    critical_crash = True
                    break
            if critical_crash:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[orchestrator] Ctrl+C received.")
    finally:
        supervisor.stop_all()
        print("[orchestrator] all collectors stopped.")
        duration_seconds = int(time.time() - start_ts)
        if post_process:
            if not scenario:
                scenario = input("[orchestrator] Scenario name for this run: ").strip()
                if not scenario:
                    scenario = "untagged"
            print(f"[orchestrator] running post-processing (scenario={scenario}, "
                  f"label={label}, duration={duration_seconds}s)...")
            bootstrap.run_post_processing(
                scenario=scenario, label=label, notes=notes,
                duration_seconds=duration_seconds,
            )
    return 1 if critical_crash else 0