from __future__ import annotations
import time
from ..runtime import bootstrap
from ..runtime.supervisor import ProcessSupervisor


class AttackPipelineController:
    """Thin wrapper around bootstrap start/stop, for scripted
    (non-interactive) callers. No polling loop, no Ctrl+C handling — the
    caller decides exactly when to stop, which is what tight attack-run
    bracketing needs."""

    def __init__(self, warmup_seconds: int = 5):
        self.warmup_seconds = warmup_seconds
        self.supervisor: ProcessSupervisor | None = None

    def start(self) -> None:
        bootstrap.create_required_directories()
        bootstrap.reset_event_log_files()
        tetra_available = bootstrap.verify_dependencies()
        self.supervisor = ProcessSupervisor()
        for name, cmd in bootstrap.build_commands(tetra_available).items():
            self.supervisor.start(name, cmd)

    def wait_ready(self) -> None:
        print(f"[pipeline] waiting {self.warmup_seconds}s for collectors to be ready...")
        time.sleep(self.warmup_seconds)

    def stop_and_postprocess(self, scenario: str, label: str,
                             notes: str | None, duration_seconds: int) -> int:
        if self.supervisor is None:
            raise RuntimeError("start() must be called before stop_and_postprocess()")
        self.supervisor.stop_all()
        print("[pipeline] all collectors stopped.")
        return bootstrap.run_post_processing(
            scenario=scenario, label=label, notes=notes,
            duration_seconds=duration_seconds,
        )