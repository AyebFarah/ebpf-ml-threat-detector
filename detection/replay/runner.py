"""
Replays a run's feature_windows rows from merged.db through the
detection pipeline in window_start_ts order, at a configurable speed, so
you can demo detection latency against a recorded attack scenario
without needing a live eBPF capture running. Once a live eBPF-driven
runner exists, it plugs into the same TieredDetector, only the source
of `window` dicts changes, process()/Alert/output.py stay identical.

Usage:
    python -m detection.replay.runner --run-id 61 --speed 10
"""
from __future__ import annotations

import argparse
import time

from detection.config import DB_PATH
from detection.data.extract import load_feature_windows
from detection.data.schema import feature_columns
from detection.inference.detector import TieredDetector
from detection.layer1.predict import Layer1Detector, load_tuned_threshold
from detection.replay import timing
from detection.replay.output import JsonlSink, to_console

def replay_run(detector: TieredDetector, df, speed: float, sink=None):
    df = df.sort_values("window_start_ts").reset_index(drop=True)
    delays = timing.compute_delays(df["window_start_ts"].tolist(), speed=speed)

    n_alerts = n_correct = 0
    for delay, (_, window) in zip(delays, df.iterrows()):
        if delay:
            time.sleep(delay)
        alert = detector.process(window.to_dict())
        if alert:
            n_alerts += 1
            n_correct += int(alert.true_label == 1)
            to_console(alert)
            if sink:
                sink.write(alert)

    print(f"\n[replay] {len(df)} windows, {n_alerts} alerts "
          f"({n_correct} true positives, {n_alerts - n_correct} false positives)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", type=int, required=True)
    ap.add_argument("--entity-type", default="flow")
    ap.add_argument("--speed", type=float, default=10.0,
                    help="playback speed multiplier; higher = faster than real time")
    ap.add_argument("--model", default="models/layer1/model.txt")
    ap.add_argument("--metrics", default="models/layer1/metrics.json",
                    help="metrics.json produced by train.py, for the tuned decision threshold")
    ap.add_argument("--output", default=None, help="optional JSONL file to also write alerts to")
    args = ap.parse_args()

    df = load_feature_windows(args.entity_type, db_path=DB_PATH)
    df = df[df.run_id == args.run_id]
    if df.empty:
        raise SystemExit(f"[replay] no '{args.entity_type}' windows for run_id={args.run_id}")

    cols = feature_columns(df)
    threshold = load_tuned_threshold(args.metrics)
    layer1 = Layer1Detector(args.model, cols, threshold=threshold)
    detector = TieredDetector(layer1)

    sink = JsonlSink(args.output) if args.output else None
    try:
        replay_run(detector, df, args.speed, sink=sink)
    finally:
        if sink:
            sink.close()

if __name__ == "__main__":
    main()
