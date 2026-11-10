"""Command-line entry points; worker commands are internal crash-test helpers."""

import argparse
import json
import os
from pathlib import Path

from .device import CHECKPOINTS, Device


def main():
    parser = argparse.ArgumentParser(description="UpdateGuard secure-update laboratory")
    commands = parser.add_subparsers(dest="command", required=True)
    benchmark = commands.add_parser("benchmark", help="Run protocol and process-crash experiments")
    benchmark.add_argument("--out", default="reports")
    benchmark.add_argument("--repetitions", type=int, default=3)
    demo = commands.add_parser("demo", help="Run a compact measured demonstration")
    demo.add_argument("--out", default="data/demo")
    install = commands.add_parser("_install-worker", help=argparse.SUPPRESS)
    install.add_argument("--device", required=True)
    install.add_argument("--image", required=True)
    install.add_argument("--crash", choices=CHECKPOINTS, required=True)
    recover = commands.add_parser("_recover-worker", help=argparse.SUPPRESS)
    recover.add_argument("--device", required=True)
    args = parser.parse_args()
    if args.command in ("benchmark", "demo"):
        from .experiments import run
        result = run(args.out, args.repetitions if args.command == "benchmark" else 1)
        print(json.dumps({key: result[key] for key in
                         ("security_cases", "recovery_cases", "security_expectations_met",
                          "recovery_invariants_met", "elapsed_seconds")}, indent=2))
        print(f"Open {Path(args.out) / 'index.html'}")
    elif args.command == "_install-worker":
        def checkpoint(name):
            if name == args.crash:
                os._exit(75)
        Device(args.device, checkpoint).install(Path(args.image).read_bytes())
    elif args.command == "_recover-worker":
        image = Device(args.device).recover()
        print(json.dumps({"version": image["version"], "healthy": image["healthy"]}))


if __name__ == "__main__":
    main()
