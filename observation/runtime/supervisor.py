import signal
import subprocess
import time


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
