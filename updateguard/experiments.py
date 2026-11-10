"""Measured protocol decisions and actual subprocess interruption campaigns."""

import csv
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from securesystemslib.exceptions import UnverifiedSignatureError
from tuf.api.exceptions import DownloadError, RepositoryError

from .client import TufClient, verify_baseline
from .common import Rejected, atomic_write, digest, encode, make_image, read_json
from .device import CHECKPOINTS, Device
from .repository import Repository
from .scenarios import DESCRIPTIONS, POLICIES, SCENARIOS, prepare
from .resources import peak_memory_bytes

EXPECTED_REJECTIONS = (Rejected, RepositoryError, DownloadError, UnverifiedSignatureError)


def security_case(name, policy, directory):
    repo = Repository()
    old = repo.view()
    baseline_key = repo.keys["targets"].public_key
    client = TufClient(directory, repo.bootstrap)
    repo.publish(make_image(2))
    # Persist previously trusted metadata before each adversarial response.
    client.fetch(files=repo.view(), floor=1)
    files = prepare(name, repo, old)
    started = time.perf_counter()
    accepted, reason, received, raw = False, "", None, None
    try:
        if policy == "tuf":
            raw, received = client.fetch(files=files, floor=2)
        else:
            raw = verify_baseline(policy, files, baseline_key)
            received = sum(len(files[p]) for p in
                ("targets/firmware.json", "plain/hash.txt" if policy == "hash" else "plain/signature.json"))
        accepted = True
    except EXPECTED_REJECTIONS as exc:
        # Keep structured reason classes. Exception strings can expose local paths.
        reason = type(exc).__name__
    elapsed = (time.perf_counter() - started) * 1000
    expected = SCENARIOS[name][POLICIES.index(policy)]
    return dict(scenario=name, policy=policy, accepted=accepted, expected=expected,
                matches_expected=accepted == expected, reason=reason,
                elapsed_ms=round(elapsed, 4), received_bytes=received,
                artifact_sha256=digest(raw) if raw else None)


def recovery_case(checkpoint, directory, healthy=True, size=256):
    root = Path(directory)
    device_path = root / "device"
    Device(device_path).initialize(make_image(1))
    raw = make_image(2, healthy=healthy, size=size)
    candidate = root / "candidate.json"
    atomic_write(candidate, raw)
    started = time.perf_counter()
    result = subprocess.run([sys.executable, "-m", "updateguard.cli", "_install-worker",
        "--device", str(device_path), "--image", str(candidate), "--crash", checkpoint],
        capture_output=True, timeout=30)
    if result.returncode != 75:
        raise RuntimeError(f"Crash worker exit {result.returncode}; expected 75")
    state_before = read_json(device_path / "state.json")
    # A different process reloads persistent state after the hard exit.
    recovered = subprocess.run([sys.executable, "-m", "updateguard.cli", "_recover-worker",
        "--device", str(device_path)], capture_output=True, timeout=30, check=True)
    status = json.loads(recovered.stdout)
    # Independent oracle reads the selected slot rather than trusting return text.
    state = read_json(device_path / "state.json")
    active = (device_path / f"slot-{state['confirmed']}.json").read_bytes()
    image = json.loads(active)
    expected_version = 2 if checkpoint in ("healthy", "committed") else 1
    valid = (image["version"] == expected_version == state["floor"] and
             image["model"] == "rover-a" and image["healthy"] is True and
             digest(active) == state["confirmed_hash"] and state["pending"] is None and
             status["version"] == image["version"])
    return dict(checkpoint=checkpoint, expected_version=expected_version,
                recovered_version=image["version"], invariant_ok=valid,
                pending_before=state_before["pending"]["phase"] if state_before["pending"] else "none",
                worker_exit=result.returncode, payload_bytes=len(raw),
                elapsed_ms=round((time.perf_counter() - started) * 1000, 3))


def write_csv(path, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run(out="reports", repetitions=3):
    if not 1 <= repetitions <= 20:
        raise ValueError("repetitions must be between 1 and 20")
    destination = Path(out)
    destination.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    security, recovery = [], []
    for repetition in range(repetitions):
        for scenario in SCENARIOS:
            for policy in POLICIES:
                with tempfile.TemporaryDirectory() as temporary:
                    row = security_case(scenario, policy, temporary)
                row["repetition"] = repetition
                security.append(row)
        for size in (256, 1024 * 1024):
            for checkpoint in CHECKPOINTS:
                with tempfile.TemporaryDirectory() as temporary:
                    row = recovery_case(checkpoint, temporary, size=size)
                row["repetition"] = repetition
                recovery.append(row)
        print(f"Completed repetition {repetition + 1}/{repetitions}", flush=True)
    write_csv(destination / "security.csv", security)
    write_csv(destination / "recovery.csv", recovery)
    source = Path(__file__).resolve().parent.parent
    manifest = dict(project="UpdateGuard", schema_version=1,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        python=platform.python_version(), platform=platform.system(),
        packages={name: importlib.metadata.version(name) for name in
                  ("tuf", "securesystemslib", "cryptography", "urllib3", "cffi", "pycparser")},
        protocol="protocol-v1", repetitions=repetitions,
        elapsed_seconds=round(time.perf_counter() - started, 3),
        parent_peak_memory_bytes=peak_memory_bytes(),
        memory_scope="Parent process only; excludes sequential child processes",
        security_cases=len(security), recovery_cases=len(recovery),
        security_expectations_met=all(r["matches_expected"] for r in security),
        recovery_invariants_met=all(r["invariant_ok"] for r in recovery),
        source_sha256={str(p.relative_to(source)).replace(os.sep, "/"): digest(p.read_bytes())
                       for p in sorted((source / "updateguard").glob("*.py"))},
        output_sha256={name: digest((destination / name).read_bytes())
                       for name in ("security.csv", "recovery.csv")},
        limitations=["Exploratory protocol tests, not real attack probabilities",
                     "Repeated cases are timing repetitions, not independent threats",
                     "Process termination at durable boundaries, not physical power loss",
                     "In-memory transport timing includes disk I/O, not network latency",
                     "Synthetic artifacts; health is a modeled boolean",
                     "Ephemeral random signing keys; outputs need not be bit-identical"])
    atomic_write(destination / "experiment.json", json.dumps(manifest, indent=2).encode())
    from .report import render
    render(destination, security, recovery, manifest)
    if not manifest["security_expectations_met"] or not manifest["recovery_invariants_met"]:
        raise RuntimeError("Experiment assertions failed; inspect exported results")
    return manifest
