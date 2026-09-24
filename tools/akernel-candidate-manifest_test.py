#!/usr/bin/env python3

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

    def test_identifies_two_architecture_artifacts(self):
        listing = self.architecture_artifacts()
        self.assertEqual(candidate.identify_layout(listing, RUN_ID), "arch")

    def test_identifies_legacy_three_artifact_candidate(self):
        listing = self.artifact_listing((
            f"gvisor-candidate-{RUN_ID}",
            f"gvisor-candidate-{RUN_ID}-amd64",
            f"gvisor-candidate-{RUN_ID}-arm64",
        ))
        self.assertEqual(candidate.identify_layout(listing, RUN_ID), "legacy")

    def test_rejects_missing_expired_or_extra_artifacts(self):
        listing = self.architecture_artifacts()
        listing["artifacts"][1]["expired"] = True
        with self.assertRaisesRegex(SystemExit, "unexpected or expired"):
            candidate.identify_layout(listing, RUN_ID)
        listing["artifacts"][1]["expired"] = False
        listing["artifacts"].append({"name": "unexpected", "expired": False})
        listing["total_count"] += 1
        with self.assertRaisesRegex(SystemExit, "unexpected or expired"):
            candidate.identify_layout(listing, RUN_ID)

    def test_rejects_incomplete_artifact_listing(self):
        listing = self.architecture_artifacts()
        listing["total_count"] += 1
        with self.assertRaisesRegex(SystemExit, "incomplete artifact listing"):
            candidate.identify_layout(listing, RUN_ID)

    @staticmethod
    def artifact_listing(names):
        artifacts = [{"name": name, "expired": False} for name in names]
        return {"total_count": len(artifacts), "artifacts": artifacts}

    @classmethod
    def architecture_artifacts(cls):
        return cls.artifact_listing(
            f"gvisor-candidate-{RUN_ID}-{arch}" for arch in ("amd64", "arm64")
        )


if __name__ == "__main__":
    unittest.main()
