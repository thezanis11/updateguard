"""Bounded artifact parsing and durable single-file writes."""

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

MAX_IMAGE = 2 * 1024 * 1024


@contextmanager
def exclusive(directory):
    """OS-managed single-writer lock, automatically released after a crash."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".writer.lock").open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise Rejected("another writer holds this state directory") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def single_writer(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with exclusive(self.directory):
            return method(self, *args, **kwargs)
    return guarded


class Rejected(ValueError):
    """A controlled policy rejection, distinct from an unexpected bug."""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    """Atomic replacement with file fsync; not a power-loss durability claim."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    return json.loads(Path(path).read_bytes())


def parse_image(raw):
    if len(raw) > MAX_IMAGE:
        raise Rejected("image too large")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Rejected("invalid image JSON") from exc
    if not isinstance(obj, dict) or set(obj) != {"model", "version", "healthy", "payload"}:
        raise Rejected("invalid image schema")
    if obj["model"] not in ("rover-a", "rover-b"):
        raise Rejected("unknown model")
    if type(obj["version"]) is not int or obj["version"] < 1:
        raise Rejected("invalid version")
    if type(obj["healthy"]) is not bool or not isinstance(obj["payload"], str):
        raise Rejected("invalid health/payload")
    return obj


def make_image(version, model="rover-a", healthy=True, size=256):
    return encode(dict(model=model, version=version, healthy=healthy, payload="x" * size))
