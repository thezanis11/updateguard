# Protocol v1 and threat model

## Objective and scope

Evaluate update-verification decisions and recoverability under explicitly constructed failures. There is no training set, learned detector or statistical estimate of attack prevalence. All artifacts are synthetic JSON objects; the publisher and device are software models. The client uses the actual `tuf.ngclient.Updater` implementation, not a replacement security algorithm.

## Trust boundaries

The bootstrap root comes from a trusted provisioning channel, never from the mutable update server. The publisher generates four ephemeral Ed25519 keys: root, targets, snapshot and timestamp, each with threshold one. Root expiry is creation time plus 365 days; normal online metadata expire after seven days. Expired cases are generated with an expiry one day in the past so reproduction does not depend on fixed calendar dates.

The local metadata cache, device journal, configured model and confirmed-version floor are protected by assumption. Tests detect accidental slot corruption, but do not defend against an administrator rewriting the journal and trusted root. A trustworthy-enough clock is required: freeze protection is bounded by metadata expiry, not an immediate detection of every withheld release. A server can always deny updates by not responding.

Consistent snapshots are disabled for this small publisher. Length/hash-linked snapshot and targets metadata still enforce the tested consistency checks. Concurrent publication races and delegated targets are outside scope.

## Comparison policies

1. **Hash:** compares SHA-256 with an unsigned digest from the same server, parses the image and checks its model. It detects accidental corruption but a malicious server can replace both bytes and digest.
2. **Signature:** verifies Ed25519 with a pinned targets key, parses the image and checks its model. It has no persistent release-version/freshness state or key-distribution protocol.
3. **TUF + application policy:** uses upstream root/metadata verification and persistent rollback/expiry checks, then requires the signed target model to match and its artifact version to exceed the confirmed device floor. Signed custom fields must agree with the downloaded artifact.

These comparisons intentionally differ in security policy, not just cryptographic primitive. The version-floor ablation test shows a freshly signed downgrade passing TUF protocol verification when the application's floor is disabled. TUF metadata versions and application release versions are distinct concepts.

Before every verification case, the TUF client sees and caches release v2. The attack or valid release is then offered. Baselines receive the same target bytes and the associated hash or detached signature. The verifier matrix measures acceptance only; it does not execute arbitrary payloads or imply that every accepted target would be activated by the full installer.

## Adversarial scenarios

The exact expected policy decisions are declared in `scenarios.py`. Tests cover corruption, replacement plus updated hash, replay, expiry, mixed metadata, incompatible model, freshly signed downgrade, exposure of only the targets key, exposure of all online keys, root substitution, targets-key rotation, use of a revoked targets key with compromised snapshot/timestamp roles, authentic unhealthy software and inconsistent signed application metadata.

"All online keys compromised" is an explicit accepted trust-limit case, not a blocked attack. In the revoked-key case, the attacker can create a matching snapshot and timestamp but cannot authorize the old target key through the trusted root. The fixed-signature baseline cannot follow authorized key rotation and therefore also demonstrates an availability failure.

## Persistent installation states

The initial confirmed image is v1 in slot A. A v2 candidate is written into the inactive slot B. The journal records `prepared`, then `trial`, then `healthy`; confirmation atomically changes the confirmed slot, digest and version floor together.

| Interruption boundary | Recovery decision |
|---|---|
| Image written, before journal | Keep v1; unused bytes are harmless |
| Prepared | Discard pending candidate and keep v1 |
| Trial | No persisted health success: keep v1 |
| Healthy | Recheck candidate integrity and complete v2 |
| Committed | Keep confirmed v2 |

An unhealthy candidate clears pending state without increasing the floor. A later repaired candidate with that same version can be retried. Once v2 is confirmed, v1 is rejected as a new installation. Recovery of v1 before v2 confirmation is therefore different from accepting a post-confirmation downgrade.

State writes use temporary files, file fsync and atomic replacement. POSIX additionally fsyncs the parent directory. Windows process-crash behavior is tested; power-loss durability is not claimed. OS locks enforce a single writer and are released when a worker terminates. The updater cache and installer have separate locks; the installer rechecks model and version so a stale concurrent verification cannot lower the floor.

## Crash oracle

A child process calls `os._exit(75)` at each named boundary, skipping normal cleanup. A newly launched child reads persistent state and runs recovery. The parent independently reads the actual confirmed slot and checks version, model, health, digest, floor and absence of pending state. Both small (about 315 bytes) and approximately 1 MiB payloads are used.

The oracle is separate from the recovery return value, but still checks the same declared software model. This is not independent physical validation. Failures inside filesystem primitives and arbitrary instruction-level interruption are outside the campaign.

## Measurements and interpretation

Default: 15 scenarios × 3 policies × 3 repetitions = 135 verifier decisions, plus 5 boundaries × 2 sizes × 3 repetitions = 30 recovery trials. Keys are newly randomized for each verifier run. Repetitions assess local timing variability; no binomial security confidence interval is reported.

Verifier time excludes repository creation and warm-up, but includes local metadata/file I/O. Byte counts are populated for accepted cases; rejected-transfer byte totals are not reported. Memory transport measurements are not network latency. The real loopback HTTP integration test confirms transport composition separately.

Recovery elapsed time includes launching both subprocesses. It is not an embedded reboot-time estimate. CSV output, installed versions, source hashes and output checksums are recorded in the manifest. Generated timestamps/keys and timing vary across machines, so reproduction means matching protocol decisions and invariants rather than byte-identical reports.

The protocol was developed while inspecting results. There is no held-out security test set, claim of attack coverage completeness or probability estimate of field failures.

## Sources

- [TUF specification](https://theupdateframework.github.io/specification/latest/)
- [python-tuf source and licenses](https://github.com/theupdateframework/python-tuf)
- [TUF updater API](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.html)
- [Python filesystem operations](https://docs.python.org/3/library/os.html)

Exact dependency versions and official distribution hashes are in `DEPENDENCY_PROVENANCE.json` and `requirements-lock.txt`. Live specification links may evolve; the implementation version is locked. No external dataset is required.
