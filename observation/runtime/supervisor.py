import signal
import subprocess
import time
import os


class ProcessSupervisor:
    def __init__(self):
        self.processes = {}

    def start(self, name: str, cmd: list):
        print(f"[main] starting {name}: {' '.join(cmd)}")
        # start_new_session=True makes this process its own process group
        # leader, with group id equal to its own pid. Every process a
        # pipeline like "tetra getevents | dispatcher" spawns underneath
        # it inherits that same group id, so we can signal all of them
        # together instead of only the immediate child.
        proc = subprocess.Popen(cmd, start_new_session=True)
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

    @staticmethod
    def _signal_group(proc, sig):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass  # whole group already gone

    def stop_all(self, timeout: int = 5):
        for name, proc in self.processes.items():
            print(f"[main] stopping {name} (pid={proc.pid})")
            self._signal_group(proc, signal.SIGINT)

        deadline = time.time() + timeout
        for name, proc in self.processes.items():
            remaining = max(0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                print(f"[main] {name} did not stop in time, terminating")
                self._signal_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print(f"[main] {name} still alive, killing")
                    self._signal_group(proc, signal.SIGKILL)
                    proc.wait()
            # A pipeline leader can exit while a piped-to process lingers:
            # sweep the group once more even after wait() succeeds.
            self._signal_group(proc, signal.SIGKILL)