# Initial validation record

- Local environment: Windows, Python 3.14.0; runtime dependency versions are recorded in the experiment manifest.
- 18 unittest tests passed, including a real loopback HTTP verification/install flow, a 45-case scenario matrix and fresh-process recovery checks.
- Standard measured campaign: 135 verifier decisions and 30 process interruptions. All declared protocol expectations and recovery invariants passed. See `reports/experiment.json` for duration, parent-process peak memory and integrity hashes.
- `scripts/check_report.py` checks source hashes, result hashes, report structure and local report links. Initial browser visual review was not completed; this check does not establish browser layout or interaction correctness.
- Gitleaks 8.30.1 found no secret in the staged public files during prepublication scanning.
- pip-audit reported no known vulnerability for the six locked runtime packages at the initial audit on 2026-11-10. This is a time-specific database result, not a security guarantee.
- The public-file inventory excludes environments, temporary data, private keys and machine-specific paths. No external dataset is redistributed.

GitHub Actions additionally runs the test suite and a measured experiment repetition on Windows and Ubuntu with Python 3.11 and 3.14. Consult the workflow status for the outcome of a particular commit.

These checks do not constitute a third-party audit, formal proof, hardware test or production-readiness certification.
