from datetime import datetime, timezone

class AttackPipelineController:
    def __init__(self, warmup_seconds: int = 5):
        self.warmup_seconds = warmup_seconds
        self.supervisor = None
        self.capture_start_ts = None

    def start(self) -> None:
        self.capture_start_ts = datetime.now(timezone.utc).isoformat()
        bootstrap.create_required_directories()
        bootstrap.reset_event_log_files()
        tetra_available = bootstrap.verify_dependencies()
        self.supervisor = ProcessSupervisor()
        for name, cmd in bootstrap.build_commands(tetra_available).items():
            self.supervisor.start(name, cmd)

    def stop_and_postprocess(self, scenario, label, notes, duration_ms=None):
        if self.supervisor is None:
            raise RuntimeError("start() must be called before stop_and_postprocess()")
        capture_end_ts = datetime.now(timezone.utc).isoformat()
        self.supervisor.stop_all()
        print("[pipeline] all collectors stopped.")
        return bootstrap.run_post_processing(
            scenario=scenario, label=label, notes=notes, duration_ms=duration_ms,
            capture_start_ts=self.capture_start_ts, capture_end_ts=capture_end_ts,
        )