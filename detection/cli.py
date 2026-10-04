"""
The single entry point of the detection package. Every subcommand only parses
arguments and calls a run() function in the right module.

Examples:
    python -m detection.cli validate --entity-type host
    python -m detection.cli train --entity-type host --model lightgbm
    python -m detection.cli compare --entity-type host --promote
    python -m detection.cli evaluate --entity-type host
    python -m detection.cli replay --run-id 61 --entity-type host --speed 5
"""
from __future__ import annotations

import argparse
import sys

from detection.config import (DB_PATH, DEFAULT_METRIC, DEFAULT_MODEL, DEFAULT_VARIANT,
                              ENTITY_TYPES)


def _entities(value: str) -> list[str]:
    return list(ENTITY_TYPES) if value == "all" else [value]


def _banner(text: str) -> None:
    print(f"\n{'=' * 60}\n{text}\n{'=' * 60}")


def cmd_validate(args):
    from detection.data.extract import load_feature_windows
    from detection.data.validate import compare_entity_types, print_report
    if args.compare:
        compare_entity_types(args.db_path)
        return
    df = load_feature_windows(args.db_path, args.entity_type)
    sys.exit(0 if print_report(df, args.entity_type) else 1)


def cmd_export(args):
    from detection.data.export import export
    for et in _entities(args.entity_type):
        export(et, db_path=args.db_path)


def cmd_train(args):
    from detection.training.train import run
    for et in _entities(args.entity_type):
        _banner(f"training model='{args.model}' entity_type='{et}'")
        run(et, model_name=args.model, db_path=args.db_path, variant=args.variant,
            show_validation=args.validate, show_split=args.show_split,
            full_metrics=args.full_metrics)


def cmd_compare(args):
    from detection.artifacts import promote
    from detection.training.compare import COMPARE_VARIANT, run, summarize
    for et in _entities(args.entity_type):
        _banner(f"comparing algorithms, entity_type='{et}'")
        ranked = summarize(run(et, db_path=args.db_path), metric=args.metric, split=args.split)
        if ranked and ranked[0][1] is not None and args.promote:
            promote(et, ranked[0][0], COMPARE_VARIANT)


def cmd_evaluate(args):
    from detection.evaluation.evaluate import run
    for et in _entities(args.entity_type):
        _banner(f"evaluating entity_type='{et}'")
        run(et, db_path=args.db_path, models=args.models, variant=args.variant)


def cmd_importance(args):
    from detection.evaluation.feature_importance import compare
    for et in _entities(args.entity_type):
        _banner(f"feature importance, entity_type='{et}'")
        df = compare(et, models=args.models, variant=args.variant)
        print(df.round(1) if not df.empty else "no models with feature_importance() found")


def cmd_generalization(args):
    from detection.evaluation.generalization import run
    run(args.entity_type, db_path=args.db_path, model_name=args.model,
        min_held_out_runs=args.min_held_out_runs)


def cmd_replay(args):
    from detection.replay.runner import run
    try:
        run(args.run_id, args.entity_type, args.model, args.variant, args.speed,
            args.db_path, args.output)
    except KeyboardInterrupt:
        raise SystemExit(130)


def cmd_report(args):
    from detection.data.extract import load_feature_windows
    from detection.evaluation.overhead import benchmark_detector
    from detection.evaluation.reports import write_report
    from detection.inference.detector import Detector
    df = load_feature_windows(args.db_path, args.entity_type)
    detector = Detector.from_artifacts(args.entity_type, args.model, args.variant)
    overhead = benchmark_detector(detector, df.head(args.n_windows))
    write_report(args.entity_type, args.model, args.variant, overhead=overhead)

def cmd_graph_build(args):
    from detection.layer2.builder import build_and_save
    build_and_save(args.db_path)


def cmd_graph_train(args):
    from detection.layer2.train import run
    params = {"epochs": args.epochs} if args.epochs and not args.baseline else None
    run(args.model, args.variant, args.baseline, args.db_path, params)


def cmd_graph_evaluate(args):
    from detection.layer2.evaluate import run
    run(args.model, args.variant, args.baseline)


def cmd_graph_compare(args):
    from detection.layer2.evaluate import compare
    compare(args.db_path, args.model, args.layer1_model, tuple(args.seq_models))


def cmd_graph_replay(args):
    from detection.layer2.predict import replay
    try:
        replay(args.run_id, args.model, args.variant, args.baseline, args.speed,
               args.db_path, args.output)
    except KeyboardInterrupt:
        raise SystemExit(130)

def _add(parser, *, entity=True, allow_all=True, variant=False, model=False, db=True):
    if entity:
        choices = list(ENTITY_TYPES) + (["all"] if allow_all else [])
        parser.add_argument("--entity-type", default="host", choices=choices)
    if variant:
        parser.add_argument("--variant", default=DEFAULT_VARIANT)
    if model:
        parser.add_argument("--model", default=DEFAULT_MODEL)
    if db:
        parser.add_argument("--db-path", default=str(DB_PATH))
    return parser

def _graph_args(parser, baseline=True):
    parser.add_argument("--model", default="graphsage",
                        choices=["graphsage", "gcn", "gru", "lstm", "cnn"])
    if baseline:
        parser.add_argument("--baseline", action="store_true",
                            help="use the graph statistics LightGBM baseline instead of a GNN")
    return parser

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="detection")
    sub = ap.add_subparsers(dest="command", required=True)

    p = _add(sub.add_parser("validate", help="ML readiness checks"))
    p.add_argument("--compare", action="store_true", help="compare all entity types")
    p.set_defaults(func=cmd_validate)

    _add(sub.add_parser("export", help="write CSV plus manifest")).set_defaults(func=cmd_export)

    p = _add(sub.add_parser("train"), variant=True, model=True)
    p.add_argument("--validate", action="store_true", help="show the data validation report")
    p.add_argument("--show-split", action="store_true", help="show train, val and test split details")
    p.add_argument("--full-metrics", action="store_true", help="show the full report for every split")
    p.set_defaults(func=cmd_train)

    p = _add(sub.add_parser("compare", help="train every algorithm and rank them"))
    p.add_argument("--metric", default=DEFAULT_METRIC)
    p.add_argument("--split", default="val", choices=["train", "val", "test"])
    p.add_argument("--promote", action="store_true", help="copy the winner to the default variant")
    p.add_argument("--seq-models", nargs="*", default=[], choices=["gru", "lstm", "cnn"],
                   help="also score these trained sequence models")
    p.set_defaults(func=cmd_compare)

    p = _add(sub.add_parser("evaluate"), variant=True)
    p.add_argument("--models", nargs="*", default=None)
    p.set_defaults(func=cmd_evaluate)

    p = _add(sub.add_parser("importance"), variant=True, db=False)
    p.add_argument("--models", nargs="*", default=None)
    p.set_defaults(func=cmd_importance)

    p = _add(sub.add_parser("generalization"), allow_all=False, model=True)
    p.add_argument("--min-held-out-runs", type=int, default=1)
    p.set_defaults(func=cmd_generalization)

    p = _add(sub.add_parser("replay"), allow_all=False, variant=True, model=True)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--speed", type=float, default=10.0)
    p.add_argument("--output", default=None, help="optional JSONL file for alerts")
    p.set_defaults(func=cmd_replay)

    p = _add(sub.add_parser("report", help="latency benchmark plus markdown report"),
             allow_all=False, variant=True, model=True)
    p.add_argument("--n-windows", type=int, default=500)
    p.set_defaults(func=cmd_report)

    p = _add(sub.add_parser("graph-build", help="build the Layer 2 graph snapshot"), entity=False)
    p.set_defaults(func=cmd_graph_build)

    p = _add(sub.add_parser("graph-train", help="train a Layer 2 model"), entity=False, variant=True)
    _graph_args(p)
    p.add_argument("--epochs", type=int, default=None)
    p.set_defaults(func=cmd_graph_train)

    p = _add(sub.add_parser("graph-evaluate", help="score the held out test runs"),
             entity=False, variant=True)
    _graph_args(p)
    p.set_defaults(func=cmd_graph_evaluate)

    p = _add(sub.add_parser("graph-compare", help="Layer 1 vs baseline vs GNN on the same test windows"),
             entity=False)
    _graph_args(p, baseline=False)
    p.add_argument("--layer1-model", default=DEFAULT_MODEL)
    p.set_defaults(func=cmd_graph_compare)

    p = _add(sub.add_parser("graph-replay", help="replay one run through a Layer 2 model"),
             entity=False, variant=True)
    _graph_args(p)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--speed", type=float, default=10.0)
    p.add_argument("--output", default=None, help="optional JSONL file for alerts")
    p.set_defaults(func=cmd_graph_replay)

    return ap


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()