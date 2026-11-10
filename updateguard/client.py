"""Real python-tuf client and deliberately limited comparison verifiers."""

import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

from securesystemslib.signer import Signature
from tuf.api.exceptions import DownloadHTTPError
from tuf.ngclient import Updater
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface

from .common import MAX_IMAGE, Rejected, digest, parse_image, single_writer


class MemoryFetcher(FetcherInterface):
    """Deterministic transport fault injection using the public TUF fetcher API."""
    def __init__(self, files):
        self.files = files
        self.bytes_received = 0
        self.requests = []

    def _fetch(self, url):
        key = unquote(urlsplit(url).path).lstrip("/")
        self.requests.append(key)
        if key not in self.files:
            raise DownloadHTTPError("not found", 404)
        data = self.files[key]
        self.bytes_received += len(data)
        return iter([data])


class TufClient:
    def __init__(self, directory, bootstrap, model="rover-a"):
        self.directory = Path(directory)
        self.bootstrap = bootstrap
        self.model = model
        for name in ("metadata", "downloads"):
            (self.directory / name).mkdir(parents=True, exist_ok=True)

    @single_writer
    def fetch(self, *, floor, files=None, base_url=None):
        if type(floor) is not int or floor < 0:
            raise ValueError("floor must be a nonnegative integer")
        fetcher = MemoryFetcher(files) if files is not None else None
        base = base_url or "https://repository.invalid/"
        updater = Updater(str(self.directory / "metadata"), base + "metadata/",
            str(self.directory / "downloads"), base + "targets/", fetcher=fetcher,
            config=UpdaterConfig(), bootstrap=self.bootstrap)
        updater.refresh()
        info = updater.get_targetinfo("firmware.json")
        if info is None:
            raise Rejected("target missing")
        custom = info.unrecognized_fields.get("custom", {})
        if custom.get("model") != self.model:
            raise Rejected("wrong model")
        if type(custom.get("version")) is not int or custom["version"] <= floor:
            raise Rejected("version is not newer than confirmed version")
        if info.length > MAX_IMAGE:
            raise Rejected("image too large")
        path = updater.download_target(info)
        raw = Path(path).read_bytes()
        image = parse_image(raw)
        if image["model"] != custom["model"] or image["version"] != custom["version"]:
            raise Rejected("signed metadata and image disagree")
        return raw, fetcher.bytes_received if fetcher else None


def verify_baseline(policy, files, public_key, model="rover-a"):
    """Both baselines check model, but lack persistent freshness/version state."""
    raw = files["targets/firmware.json"]
    if policy == "hash":
        if digest(raw).encode() != files["plain/hash.txt"]:
            raise Rejected("hash mismatch")
    elif policy == "signature":
        signature = Signature.from_dict(json.loads(files["plain/signature.json"]))
        public_key.verify_signature(signature, raw)
    else:
        raise ValueError(policy)
    if parse_image(raw)["model"] != model:
        raise Rejected("wrong model")
    return raw
