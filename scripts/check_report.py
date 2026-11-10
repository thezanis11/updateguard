"""Check source/output integrity and the static structure of a measured report."""

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import sys


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.rows = 0
        self.local_links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            if attrs["id"] in self.ids:
                raise ValueError("duplicate HTML id")
            self.ids.add(attrs["id"])
        if tag == "tr":
            self.rows += 1
        if tag == "a" and "href" in attrs and ":" not in attrs["href"]:
            self.local_links.append(attrs["href"])


def main():
    root = Path(__file__).resolve().parent.parent
    report = root / (sys.argv[1] if len(sys.argv) > 1 else "reports")
    manifest = json.loads((report / "experiment.json").read_text(encoding="utf-8"))
    for base, key in ((root, "source_sha256"), (report, "output_sha256")):
        for relative, expected in manifest[key].items():
            actual = hashlib.sha256((base / relative).read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"Integrity mismatch: {relative}")
    parser = ReportParser()
    document = (report / "index.html").read_text(encoding="utf-8")
    parser.feed(document)
    if not {"matrix", "filter"} <= parser.ids or parser.rows != 22:
        raise ValueError("Unexpected report structure")
    if any(not (report / link).is_file() for link in parser.local_links):
        raise ValueError("Broken local report link")
    if any(token in document for token in ("SECURITY_ROWS", "RECOVERY_ROWS", "ASSERTION_STATE")):
        raise ValueError("Unexpanded report placeholder")
    print("Source hashes, result hashes and report structure verified")


if __name__ == "__main__":
    main()
