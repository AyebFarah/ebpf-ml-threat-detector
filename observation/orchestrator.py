import time
from observation.runtime import bootstrap
from observation.runtime.supervisor import ProcessSupervisor

def run(post_process: bool = True) -> int:
    bootstrap.create_required_directories()
    bootstrap.reset_event_log_files()
    tetra_available = bootstrap.verify_dependencies()
    supervisor = ProcessSupervisor()
    for name, cmd in bootstrap.build_commands(tetra_available).items():
        supervisor.start(name, cmd)
    print("[orchestrator] pipeline running. Press Ctrl+C to stop.")
    critical_crash = False
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
        if post_process:
            print("[orchestrator] running post-processing...")
            bootstrap.run_post_processing()
    return 1 if critical_crash else 0