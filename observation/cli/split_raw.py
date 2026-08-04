#!/usr/bin/env python3
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from dispatcher import dispatch_raw_event


def process_file(path: Path):
    print(f"[+] Processing: {path}")
    count = 0
    errors = 0

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                dispatch_raw_event(event)
                count += 1
            except json.JSONDecodeError:
                errors += 1
                print(f"    [!] JSON error on line {line_num}")

    print(f"    → {count} events dispatched ({errors} errors)")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cli/split_raw.py <raw_file.json | raw_folder/>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if target.is_file():
        process_file(target)
    elif target.is_dir():
        files = sorted(target.glob("*.json"))
        if not files:
            print(f"No .json files found in {target}")
            sys.exit(1)
        for f in files:
            process_file(f)
    else:
        print(f"Not found: {target}")
        sys.exit(1)

    print("\nDone. Check samples/event_logs_by_policy/")


if __name__ == "__main__":
    main()
