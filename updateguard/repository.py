"""Ephemeral publisher. Private keys only live in memory, never in reports."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, Root, Snapshot, TargetFile, Targets, Timestamp

from .common import digest, encode, make_image, parse_image


class Repository:
    def __init__(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.keys = {role: CryptoSigner.generate_ed25519() for role in
                     ("root", "targets", "snapshot", "timestamp")}
        root = Root(version=1, expires=self.now + timedelta(days=365), consistent_snapshot=False)
        for role, signer in self.keys.items():
            root.add_key(signer.public_key, role)
        self.root = Metadata(root)
        self.root.sign(self.keys["root"])
        self.bootstrap = self.root.to_bytes()
        self.files = {"metadata/1.root.json": self.bootstrap}
        self.publish(make_image(1))

    def publish(self, raw, revision=None, expired=False):
        image = parse_image(raw)
        if revision is None:
            revision = getattr(self, "revision", 0) + 1
        self.revision = revision
        expiry = self.now + timedelta(days=-1 if expired else 7)
        target = TargetFile.from_data("firmware.json", raw)
        target.unrecognized_fields["custom"] = {
            "model": image["model"], "version": image["version"]}
        self.targets = Metadata(Targets(version=revision, expires=expiry,
                                        targets={"firmware.json": target}))
        self.targets.sign(self.keys["targets"])
        targets_raw = self.targets.to_bytes()
        self.snapshot = Metadata(Snapshot(version=revision, expires=expiry,
            meta={"targets.json": MetaFile.from_data(revision, targets_raw, ["sha256"])}))
        self.snapshot.sign(self.keys["snapshot"])
        snapshot_raw = self.snapshot.to_bytes()
        self.timestamp = Metadata(Timestamp(version=revision, expires=expiry,
            snapshot_meta=MetaFile.from_data(revision, snapshot_raw, ["sha256"])))
        self.timestamp.sign(self.keys["timestamp"])
        self.files.update({"metadata/targets.json": targets_raw,
            "metadata/snapshot.json": snapshot_raw,
            "metadata/timestamp.json": self.timestamp.to_bytes(),
            "targets/firmware.json": raw,
            "plain/hash.txt": digest(raw).encode(),
            "plain/signature.json": encode(self.keys["targets"].sign(raw).to_dict())})

    def view(self):
        return deepcopy(self.files)

    def rotate_targets_key(self):
        """Root-authorized target key revocation; root key itself is unchanged."""
        old = self.keys["targets"]
        self.root.signed.revoke_key(old.public_key.keyid, "targets")
        self.keys["targets"] = CryptoSigner.generate_ed25519()
        self.root.signed.add_key(self.keys["targets"].public_key, "targets")
        self.root.signed.version += 1
        self.root.sign(self.keys["root"])
        self.files[f"metadata/{self.root.signed.version}.root.json"] = self.root.to_bytes()
        return old
