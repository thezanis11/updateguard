"""Explicit adversary capabilities and expected verifier decisions."""

from datetime import timedelta

from tuf.api.metadata import MetaFile, Metadata, Snapshot, Timestamp

from .common import digest, encode, make_image

POLICIES = ("hash", "signature", "tuf")
# Expected decisions are protocol assertions, not empirical attack probabilities.
SCENARIOS = {
    "legitimate": (True, True, True),
    "corrupt_download": (False, False, False),
    "replace_file_and_hash": (True, False, False),
    "replay_old_release": (True, True, False),
    "expired_metadata": (True, True, False),
    "mixed_metadata": (True, True, False),
    "wrong_model": (False, False, False),
    "signed_downgrade": (True, True, False),
    "targets_key_compromised": (True, True, False),
    "all_online_keys_compromised": (True, True, True),
    "root_substitution": (True, False, False),
    "key_rotation": (True, False, True),
    "revoked_targets_key": (True, True, False),
    "health_failure": (True, True, True),
    "metadata_image_mismatch": (True, True, False),
}
DESCRIPTIONS = {
    "legitimate": "Authorized v3 for rover-a",
    "corrupt_download": "Transport changes the artifact but not its hash/signature",
    "replace_file_and_hash": "Mirror changes artifact and unsigned hash; no signing keys",
    "replay_old_release": "Mirror replays v1 after the client has seen v2",
    "expired_metadata": "Signed release is expired at refresh time",
    "mixed_metadata": "New snapshot served with old targets metadata",
    "wrong_model": "Valid signed artifact for rover-b delivered to rover-a",
    "signed_downgrade": "Publisher signs v1 in newer metadata; local floor remains v2",
    "targets_key_compromised": "Only targets signing key exposed; snapshot remains trusted",
    "all_online_keys_compromised": "Targets, snapshot and timestamp keys exposed: known trust limit",
    "root_substitution": "Attacker supplies a new self-signed root, not authorized by old root",
    "key_rotation": "Root authorizes new targets key; naive signature client retains old key",
    "revoked_targets_key": "Revoked targets key plus current snapshot/timestamp keys exposed",
    "health_failure": "Authentic newer image fails the modeled health check",
    "metadata_image_mismatch": "Publisher signs inconsistent custom version and payload version",
}


def rechain(repo):
    """Publisher/compromised online roles sign a fresh chain around targets."""
    raw = repo.targets.to_bytes()
    expiry = repo.now + timedelta(days=7)
    repo.snapshot = Metadata(Snapshot(version=repo.revision, expires=expiry,
        meta={"targets.json": MetaFile.from_data(repo.revision, raw, ["sha256"])}))
    repo.snapshot.sign(repo.keys["snapshot"])
    snapshot_raw = repo.snapshot.to_bytes()
    repo.timestamp = Metadata(Timestamp(version=repo.revision, expires=expiry,
        snapshot_meta=MetaFile.from_data(repo.revision, snapshot_raw, ["sha256"])))
    repo.timestamp.sign(repo.keys["timestamp"])
    repo.files.update({"metadata/targets.json": raw, "metadata/snapshot.json": snapshot_raw,
                       "metadata/timestamp.json": repo.timestamp.to_bytes()})


def prepare(name, repo, old_view):
    if name not in SCENARIOS:
        raise ValueError(name)
    repo.publish(make_image(3, model="rover-b" if name == "wrong_model" else "rover-a",
                            healthy=name != "health_failure"),
                 expired=name == "expired_metadata")
    if name == "replay_old_release":
        return old_view
    if name == "mixed_metadata":
        repo.files["metadata/targets.json"] = old_view["metadata/targets.json"]
    if name in ("corrupt_download", "replace_file_and_hash"):
        raw = make_image(99)
        repo.files["targets/firmware.json"] = raw
        if name == "replace_file_and_hash":
            repo.files["plain/hash.txt"] = digest(raw).encode()
    if name == "signed_downgrade":
        repo.publish(make_image(1))
    if name == "targets_key_compromised":
        trusted_snapshot = repo.files["metadata/snapshot.json"]
        trusted_timestamp = repo.files["metadata/timestamp.json"]
        repo.publish(make_image(99))
        repo.files["metadata/snapshot.json"] = trusted_snapshot
        repo.files["metadata/timestamp.json"] = trusted_timestamp
    if name == "all_online_keys_compromised":
        repo.publish(make_image(99))
    if name == "root_substitution":
        from .repository import Repository
        attacker = Repository()
        attacker.root.signed.version = 2
        attacker.root.sign(attacker.keys["root"])
        attacker.files["metadata/2.root.json"] = attacker.root.to_bytes()
        attacker.publish(make_image(99), revision=10)
        return attacker.view()
    if name in ("key_rotation", "revoked_targets_key"):
        old_signer = repo.rotate_targets_key()
        repo.publish(make_image(4))
        if name == "revoked_targets_key":
            repo.targets.sign(old_signer)
            rechain(repo)
            repo.files["plain/signature.json"] = encode(
                old_signer.sign(repo.files["targets/firmware.json"]).to_dict())
    if name == "metadata_image_mismatch":
        repo.targets.signed.targets["firmware.json"].unrecognized_fields["custom"]["version"] = 8
        repo.targets.sign(repo.keys["targets"])
        rechain(repo)
    return repo.view()
