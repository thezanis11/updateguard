"""Single-writer A/B installation model with explicit recovery transitions."""

from pathlib import Path

from .common import Rejected, atomic_write, digest, encode, parse_image, read_json, single_writer

CHECKPOINTS = ("image_written", "prepared", "trial", "healthy", "committed")


class Device:
    def __init__(self, directory, checkpoint=None):
        self.directory = Path(directory)
        self.checkpoint = checkpoint or (lambda name: None)

    @property
    def state_path(self):
        return self.directory / "state.json"

    def slot_path(self, slot):
        if slot not in ("A", "B"):
            raise Rejected("invalid slot")
        return self.directory / f"slot-{slot}.json"

    @single_writer
    def initialize(self, raw):
        if self.state_path.exists():
            raise Rejected("device already initialized")
        image = parse_image(raw)
        if not image["healthy"]:
            raise Rejected("initial image unhealthy")
        atomic_write(self.slot_path("A"), raw)
        self._write(dict(model=image["model"], confirmed="A", floor=image["version"],
                         confirmed_hash=digest(raw), pending=None))

    def _write(self, state):
        atomic_write(self.state_path, encode(state))

    def state(self):
        return read_json(self.state_path)

    def _checked_slot(self, slot, expected_hash, state):
        raw = self.slot_path(slot).read_bytes()
        if digest(raw) != expected_hash:
            raise Rejected("slot integrity failure")
        image = parse_image(raw)
        if image["model"] != state["model"]:
            raise Rejected("slot model mismatch")
        return image

    @single_writer
    def recover(self):
        return self._recover()

    def _recover(self):
        state = self.state()
        pending = state["pending"]
        if pending and pending["phase"] == "healthy":
            try:
                candidate = self._checked_slot(pending["slot"], pending["hash"], state)
                if not candidate["healthy"] or candidate["version"] <= state["floor"]:
                    raise Rejected("invalid healthy candidate")
            except (OSError, ValueError):
                state["pending"] = None
            else:
                state.update(confirmed=pending["slot"], confirmed_hash=pending["hash"],
                             floor=candidate["version"], pending=None)
            self._write(state)
        elif pending:
            state["pending"] = None
            self._write(state)
        image = self._checked_slot(state["confirmed"], state["confirmed_hash"], state)
        if image["version"] != state["floor"] or not image["healthy"]:
            raise Rejected("invalid confirmed image")
        return image

    @single_writer
    def install(self, raw):
        """Caller supplies verified bytes. This layer also checks model/version."""
        self._recover()
        state = self.state()
        image = parse_image(raw)
        if image["model"] != state["model"] or image["version"] <= state["floor"]:
            raise Rejected("incompatible model or non-increasing version")
        slot = "B" if state["confirmed"] == "A" else "A"
        atomic_write(self.slot_path(slot), raw)
        self.checkpoint("image_written")
        state["pending"] = dict(slot=slot, hash=digest(raw), phase="prepared")
        self._write(state)
        self.checkpoint("prepared")
        state["pending"]["phase"] = "trial"
        self._write(state)
        self.checkpoint("trial")
        image = self._checked_slot(slot, digest(raw), state)
        if not image["healthy"]:
            state["pending"] = None
            self._write(state)
            return False
        state["pending"]["phase"] = "healthy"
        self._write(state)
        self.checkpoint("healthy")
        self._recover()
        self.checkpoint("committed")
        return True
