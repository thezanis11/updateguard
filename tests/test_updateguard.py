import functools
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from updateguard.client import TufClient
from updateguard.common import Rejected, atomic_write, digest, encode, make_image, parse_image, exclusive
from updateguard.device import CHECKPOINTS, Device
from updateguard.experiments import recovery_case, security_case
from updateguard.repository import Repository
from updateguard.scenarios import POLICIES, SCENARIOS


class LabTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def device(self, checkpoint=None):
        device = Device(self.root / "device", checkpoint)
        device.initialize(make_image(1))
        return device

    def test_all_threats_have_expected_decisions(self):
        for scenario in SCENARIOS:
            for policy in POLICIES:
                with self.subTest(scenario=scenario, policy=policy):
                    row = security_case(scenario, policy, self.root / scenario / policy)
                    self.assertEqual(row["accepted"], row["expected"], row)

    def test_crash_recovery_in_fresh_processes(self):
        for point in CHECKPOINTS:
            with self.subTest(point=point):
                row = recovery_case(point, self.root / point)
                self.assertTrue(row["invariant_ok"], row)

    def test_unhealthy_signed_update_keeps_confirmed_version(self):
        repo = Repository()
        repo.publish(make_image(2, healthy=False))
        raw, _ = TufClient(self.root / "client", repo.bootstrap).fetch(files=repo.view(), floor=1)
        device = self.device()
        self.assertFalse(device.install(raw))
        self.assertEqual(device.recover()["version"], 1)
        self.assertEqual(device.state()["floor"], 1)

    def test_confirmed_floor_survives_recreation(self):
        device = self.device()
        device.install(make_image(2))
        replacement = Device(device.directory)
        with self.assertRaises(Rejected):
            replacement.install(make_image(1))
        self.assertEqual(replacement.recover()["version"], 2)

    def test_recovery_idempotence(self):
        device = self.device()
        device.install(make_image(2))
        before = device.state_path.read_bytes()
        for _ in range(3):
            self.assertEqual(device.recover()["version"], 2)
        self.assertEqual(before, device.state_path.read_bytes())

    def test_corrupt_active_slot_fails_closed(self):
        device = self.device()
        device.slot_path("A").write_bytes(make_image(99))
        with self.assertRaises(Rejected):
            device.recover()

    def test_corrupt_healthy_candidate_recovers_old_image(self):
        class Stop(Exception):
            pass
        def checkpoint(name):
            if name == "healthy":
                raise Stop()
        device = self.device(checkpoint)
        with self.assertRaises(Stop):
            device.install(make_image(2))
        device.slot_path("B").write_bytes(b"broken")
        self.assertEqual(Device(device.directory).recover()["version"], 1)

    def test_wrong_model_does_not_touch_confirmed_image(self):
        device = self.device()
        before = device.state_path.read_bytes()
        with self.assertRaises(Rejected):
            device.install(make_image(2, model="rover-b"))
        self.assertEqual(before, device.state_path.read_bytes())

    def test_three_successive_updates_reuse_slots_safely(self):
        device = self.device()
        for version in range(2, 5):
            self.assertTrue(device.install(make_image(version)))
            self.assertEqual(device.recover()["version"], version)
        self.assertEqual(device.state()["confirmed"], "B")

    def test_repeated_initialization_rejected(self):
        device = self.device()
        with self.assertRaises(Rejected):
            device.initialize(make_image(1))

    def test_second_writer_rejected_then_lock_released(self):
        device = self.device()
        with exclusive(device.directory):
            with self.assertRaises(Rejected):
                device.install(make_image(2))
        self.assertTrue(device.install(make_image(2)))

    def test_payload_schema_and_size(self):
        for raw in (b"[]", b"null", b"not json", make_image(True),
                    make_image(0), make_image(2, healthy="yes"), make_image(2, size=3 * 1024 * 1024)):
            with self.subTest(length=len(raw)), self.assertRaises(Rejected):
                parse_image(raw)

    def test_target_hash_mismatch_same_length(self):
        repo = Repository()
        repo.publish(make_image(2))
        files = repo.view()
        files["targets/firmware.json"] = files["targets/firmware.json"].replace(b'xxx', b'yyy', 1)
        from tuf.api.exceptions import LengthOrHashMismatchError
        with self.assertRaises(LengthOrHashMismatchError):
            TufClient(self.root / "client", repo.bootstrap).fetch(files=files, floor=1)

    def test_metadata_cache_rejects_rollback_after_client_restart(self):
        repo = Repository()
        old = repo.view()
        repo.publish(make_image(2))
        TufClient(self.root / "client", repo.bootstrap).fetch(files=repo.view(), floor=1)
        from tuf.api.exceptions import BadVersionNumberError
        with self.assertRaises(BadVersionNumberError):
            TufClient(self.root / "client", repo.bootstrap).fetch(files=old, floor=0)

    def test_version_floor_ablation(self):
        repo = Repository()
        repo.publish(make_image(2))
        client = TufClient(self.root / "client", repo.bootstrap)
        client.fetch(files=repo.view(), floor=1)
        repo.publish(make_image(1))
        raw, _ = client.fetch(files=repo.view(), floor=0)
        self.assertEqual(parse_image(raw)["version"], 1)
        with self.assertRaises(Rejected):
            client.fetch(files=repo.view(), floor=2)

    def test_bootstrap_not_trusted_from_download_server(self):
        trusted, attacker = Repository(), Repository()
        attacker.publish(make_image(2))
        from tuf.api.exceptions import UnsignedMetadataError
        with self.assertRaises(UnsignedMetadataError):
            TufClient(self.root / "client", trusted.bootstrap).fetch(files=attacker.view(), floor=1)

    def test_health_recovery_allows_retry_of_same_candidate_version(self):
        device = self.device()
        self.assertFalse(device.install(make_image(2, healthy=False)))
        self.assertTrue(device.install(make_image(2, healthy=True)))
        self.assertEqual(device.recover()["version"], 2)

    def test_actual_http_transport(self):
        repo = Repository()
        repo.publish(make_image(2))
        served = self.root / "served"
        for path, raw in repo.view().items():
            atomic_write(served / path, raw)
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        handler = functools.partial(QuietHandler, directory=str(served))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            raw, received = TufClient(self.root / "http-client", repo.bootstrap).fetch(
                base_url=f"http://127.0.0.1:{server.server_port}/", floor=1)
            self.assertEqual(parse_image(raw)["version"], 2)
            self.assertIsNone(received)
            device = self.device()
            self.assertTrue(device.install(raw))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
