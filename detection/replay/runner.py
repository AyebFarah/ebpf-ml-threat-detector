from __future__ import annotations

import time

from detection.config import DB_PATH, DEFAULT_MODEL, DEFAULT_VARIANT
from detection.data.extract import load_feature_windows
from detection.inference.detector import Detector
from detection.replay import timing
from detection.replay.output import JsonlSink, to_console


def replay_run(detector: Detector, df, speed: float, sink=None) -> dict:
    df = df.sort_values("window_start_ts").reset_index(drop=True)
    delays = timing.compute_delays(df["window_start_ts"].tolist(), speed=speed)
    run_start = df["window_start_ts"].iloc[0]

    n_alerts = n_true = 0
    seconds_to_first_alert = None
    interrupted = False
    try:
        for delay, (_, window) in zip(delays, df.iterrows()):
            if delay:
                time.sleep(delay)
            alert = detector.process(window.to_dict())
            if alert is None:
                continue
            n_alerts += 1
            n_true += int(alert.true_label == 1)
            if seconds_to_first_alert is None:
                seconds_to_first_alert = timing.seconds_between(run_start, alert.window_end_ts)
            to_console(alert)
            if sink:
                sink.write(alert)
    except KeyboardInterrupt:
        interrupted = True
        print("\n[replay] stopped early by user")

    summary = {"windows": len(df), "alerts": n_alerts, "true_positives": n_true,
               "false_positives": n_alerts - n_true,
               "seconds_to_first_alert": seconds_to_first_alert,
               "interrupted": interrupted}
    tag = " (partial, interrupted)" if interrupted else ""
    print(f"\n[replay] {summary['windows']} windows total, {n_alerts} alerts so far{tag} "
          f"({n_true} true positives, {n_alerts - n_true} false positives)")
    if seconds_to_first_alert is not None:
        print(f"[replay] first alert {seconds_to_first_alert:.1f}s after the first window of the run")
    return summary


def run(run_id: int, entity_type: str = "flow", model_name: str = DEFAULT_MODEL,
        variant: str = DEFAULT_VARIANT, speed: float = 10.0, db_path=DB_PATH,
        output: str | None = None) -> dict:
    df = load_feature_windows(db_path, entity_type)
    df = df[df.run_id == run_id]
    if df.empty:
        raise SystemExit(f"[replay] no '{entity_type}' windows for run_id={run_id}")

    detector = Detector.from_artifacts(entity_type, model_name, variant)
    sink = JsonlSink(output) if output else None
    try:
        return replay_run(detector, df, speed, sink=sink)
    finally:
        if sink:
            sink.close()