#!/usr/bin/env python3
"""Exercise candidate metadata and cross-architecture validation."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "candidate_manifest", Path(__file__).with_name("akernel-candidate-manifest.py")
)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)

REPOSITORY = "akernel-dev/gvisor"
COMMIT = "a" * 40
TAG = "release-20260817.0-akernel.4"
RUN_ID = "12345"


class CandidateManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for arch in ("amd64", "arm64"):
            asset_dir = self.root / f"gvisor-candidate-{RUN_ID}-{arch}"
            asset_dir.mkdir()
            archive = asset_dir / f"gvisor-{arch}.tar.bz2"
            with tarfile.open(archive, "w:bz2") as bundle:
                payload = arch.encode()
                info = tarfile.TarInfo("runsc")
                info.size = len(payload)
                bundle.addfile(info, io.BytesIO(payload))
            digest = hashlib.sha512(archive.read_bytes()).hexdigest()
            archive.with_name(f"{archive.name}.sha512").write_text(
                f"{digest}  {archive.name}\n"
            )
            candidate.create_arch(
                arch, archive, REPOSITORY, COMMIT, TAG, RUN_ID,
                asset_dir / f"candidate-{arch}.json",
            )

    def assemble(self):
        output = self.root / "manifest.json"
        with patch.object(candidate.subprocess, "run") as git:
            git.return_value.stdout = "a" * 40 + " test change\n"
            candidate.assemble(self.root, REPOSITORY, COMMIT, RUN_ID, output)
        return json.loads(output.read_text())

    def test_two_architecture_artifacts_produce_one_release_manifest(self):
        manifest = self.assemble()
        self.assertEqual(manifest["schema"], 4)
        self.assertEqual(manifest["release_tag"], TAG)
        self.assertEqual(set(manifest["archives"]), {"amd64", "arm64"})
        self.assertEqual(manifest["contents"], "runsc")

    def test_rejects_checksum_mismatch(self):
        checksum = self.root / f"gvisor-candidate-{RUN_ID}-arm64/gvisor-arm64.tar.bz2.sha512"
        checksum.write_text("0" * 128 + "  gvisor-arm64.tar.bz2\n")
        with self.assertRaisesRegex(SystemExit, "invalid checksum"):
            self.assemble()

    def test_rejects_mixed_release_tags(self):
        metadata = self.root / f"gvisor-candidate-{RUN_ID}-arm64/candidate-arm64.json"
        value = json.loads(metadata.read_text())
        value["release_tag"] = "release-20260817.0-akernel.5"
        metadata.write_text(json.dumps(value))
        with self.assertRaisesRegex(SystemExit, "architecture metadata differs"):
            self.assemble()


if __name__ == "__main__":
    unittest.main()
