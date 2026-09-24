"""
Single entry point for the whole detection pipeline. Thin by design
each subcommand just calls the corresponding module's main(), so
`python -m detection.layer1.train` and `python -m detection.cli
train-layer1` do exactly the same thing: use whichever is more
convenient.

Usage:
    python -m detection.cli validate --entity-type flow
    python -m detection.cli train-layer1
    python -m detection.cli evaluate-layer1
    python -m detection.cli replay --run-id 61 --speed 10
"""
from __future__ import annotations

import argparse
import sys


def cmd_validate(args):
    from detection.data.extract import load_feature_windows
    from detection.data.validate import print_report
    df = load_feature_windows(args.entity_type)
    ok = print_report(df, args.entity_type)
    sys.exit(0 if ok else 1)


def cmd_train_layer1(args):
    sys.argv = ["train.py", "--entity-type", args.entity_type]
    from detection.layer1.train import main
    main()


def cmd_evaluate_layer1(args):
    sys.argv = ["evaluate.py", "--entity-type", args.entity_type]
    from detection.layer1.evaluate import main
    main()


def cmd_evaluate_generalization(args):
    sys.argv = ["generalization.py", "--entity-type", args.entity_type,
                "--min-held-out-runs", str(args.min_held_out_runs)]
    from detection.evaluation.generalization import main
    main()


def cmd_replay(args):
    sys.argv = ["runner.py", "--run-id", str(args.run_id), "--speed", str(args.speed)]
    from detection.replay.runner import main
    main()


def main():
    ap = argparse.ArgumentParser(prog="detection")
    sub = ap.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate")
    p_validate.add_argument("--entity-type", default="flow")
    p_validate.set_defaults(func=cmd_validate)

    p_train1 = sub.add_parser("train-layer1")
    p_train1.add_argument("--entity-type", default="flow")
    p_train1.set_defaults(func=cmd_train_layer1)

    p_eval1 = sub.add_parser("evaluate-layer1")
    p_eval1.add_argument("--entity-type", default="flow")
    p_eval1.set_defaults(func=cmd_evaluate_layer1)

    p_gen = sub.add_parser("evaluate-generalization")
    p_gen.add_argument("--entity-type", default="flow")
    p_gen.add_argument("--min-held-out-runs", type=int, default=1)
    p_gen.set_defaults(func=cmd_evaluate_generalization)

    p_replay = sub.add_parser("replay")
    p_replay.add_argument("--run-id", type=int, required=True)
    p_replay.add_argument("--speed", type=float, default=10.0)
    p_replay.set_defaults(func=cmd_replay)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
