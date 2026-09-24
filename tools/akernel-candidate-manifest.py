#!/usr/bin/env python3
"""Describe and assemble the two architecture-specific AKernel candidates."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


ARCHES = ("amd64", "arm64")
TAG_PATTERN = re.compile(r"^(release-[0-9]{8}\.[0-9]+)-akernel\.[1-9][0-9]*$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def digest_and_contents(archive):
    hasher = hashlib.sha512()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    expected_checksum = f"{digest}  {archive.name}\n"
    checksum = archive.with_name(f"{archive.name}.sha512")
    require(checksum.read_text() == expected_checksum, f"invalid checksum: {checksum}")
    with tarfile.open(archive, "r:bz2") as bundle:
        contents = sorted(member.name for member in bundle if not member.isdir())
    return digest, "\n".join(contents)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def create_arch(arch, archive, repository, commit, release_tag, run_id, output):
    require(arch in ARCHES, f"invalid architecture: {arch}")
    require(archive.name == f"gvisor-{arch}.tar.bz2", "invalid archive name")
    tag = TAG_PATTERN.fullmatch(release_tag)
    require(tag is not None, f"invalid release tag: {release_tag}")
    require(COMMIT_PATTERN.fullmatch(commit) is not None, "invalid commit")
    require(run_id.isdecimal() and int(run_id) > 0, "invalid run ID")
    digest, contents = digest_and_contents(archive)
    write_json(output, {
        "schema": 1,
        "repository": repository,
        "commit": commit,
        "upstream_tag": tag.group(1),
        "release_tag": release_tag,
        "workflow_run_id": run_id,
        "arch": arch,
        "archive": {"name": archive.name, "sha512": digest},
        "contents": contents,
    })


def assemble(directory, repository, commit, run_id, output):
    require(COMMIT_PATTERN.fullmatch(commit) is not None, "invalid commit")
    require(run_id.isdecimal() and int(run_id) > 0, "invalid run ID")
    metadata = {}
    for arch in ARCHES:
        asset_dir = directory / f"gvisor-candidate-{run_id}-{arch}"
        archive = asset_dir / f"gvisor-{arch}.tar.bz2"
        description = json.loads((asset_dir / f"candidate-{arch}.json").read_text())
        digest, contents = digest_and_contents(archive)
        tag = TAG_PATTERN.fullmatch(description.get("release_tag", ""))
        require(tag is not None, f"invalid release tag for {arch}")
        expected = {
            "schema": 1,
            "repository": repository,
            "commit": commit,
            "upstream_tag": tag.group(1),
            "release_tag": description["release_tag"],
            "workflow_run_id": run_id,
            "arch": arch,
            "archive": {"name": archive.name, "sha512": digest},
            "contents": contents,
        }
        require(description == expected, f"invalid candidate metadata for {arch}")
        metadata[arch] = description

    amd64, arm64 = (metadata[arch] for arch in ARCHES)
    for field in ("repository", "commit", "upstream_tag", "release_tag", "workflow_run_id", "contents"):
        require(amd64[field] == arm64[field], f"architecture metadata differs: {field}")

    changes = subprocess.run(
        ["git", "log", "--format=%H %s", f"{amd64['upstream_tag']}..{commit}"],
        check=True, capture_output=True, text=True,
    ).stdout.rstrip("\n")
    write_json(output, {
        "schema": 4,
        "repository": repository,
        "commit": commit,
        "upstream_tag": amd64["upstream_tag"],
        "release_tag": amd64["release_tag"],
        "workflow_run_id": run_id,
        "archives": {arch: metadata[arch]["archive"] for arch in ARCHES},
        "contents": amd64["contents"],
        "changes": changes,
    })


if __name__ == "__main__":
    command, *args = sys.argv[1:]
    if command == "create-arch" and len(args) == 7:
        arch, archive, repository, commit, release_tag, run_id, output = args
        create_arch(arch, Path(archive), repository, commit, release_tag, run_id, Path(output))
    elif command == "assemble" and len(args) == 5:
        directory, repository, commit, run_id, output = args
        assemble(Path(directory), repository, commit, run_id, Path(output))
    else:
        raise SystemExit("usage: akernel-candidate-manifest.py create-arch ARCH ARCHIVE REPO COMMIT TAG RUN_ID OUTPUT | assemble DIR REPO COMMIT RUN_ID OUTPUT")
