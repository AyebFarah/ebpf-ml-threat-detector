import time
from .runtime import bootstrap
from .runtime.supervisor import ProcessSupervisor


def start_pipeline() -> ProcessSupervisor:
    """Prepares directories/logs, starts all collectors, returns the
    running supervisor. Shared by the interactive CLI (run()) and any
    scripted caller that needs manual control over the stop point
    (e.g. the attack-lab wrapper)."""
    bootstrap.create_required_directories()
    bootstrap.reset_event_log_files()
    tetra_available = bootstrap.verify_dependencies()
    supervisor = ProcessSupervisor()
    for name, cmd in bootstrap.build_commands(tetra_available).items():
        supervisor.start(name, cmd)
    return supervisor


def stop_pipeline_and_postprocess(supervisor: ProcessSupervisor, scenario: str,
                                  label: str, notes: str | None,
                                  duration_seconds: int) -> int:
    """Stops all collectors and runs post-processing (normalize/correlate/
    load). Returns the resulting run_id."""
    supervisor.stop_all()
    print("[orchestrator] all collectors stopped.")
    print(f"[orchestrator] running post-processing (scenario={scenario}, "
          f"label={label}, duration={duration_seconds}s)...")
    return bootstrap.run_post_processing(
        scenario=scenario, label=label, notes=notes,
        duration_seconds=duration_seconds,
    )


def run(post_process: bool = True, scenario: str | None = None,
        label: str = "benign", notes: str | None = None) -> int:
    supervisor = start_pipeline()
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
        duration_seconds = int(time.time() - start_ts)
        if post_process:
            if not scenario:
                scenario = input("[orchestrator] Scenario name for this run: ").strip()
                if not scenario:
                    scenario = "untagged"
            stop_pipeline_and_postprocess(supervisor, scenario, label, notes, duration_seconds)
        else:
            supervisor.stop_all()
            print("[orchestrator] all collectors stopped.")
    return 1 if critical_crash else 0