#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise rinpack's manifest-root and source-file identity checks."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


MANIFEST = '''[package]
package_id = "org.rinos.toctou-test"
display_name = "Rinpack TOCTOU Test"
version = "1.0.0"
architecture = "any"
package_type = "application"
description = "Source identity integration test."
license = "MIT"
homepage = "https://example.invalid"
min_rinos_version = "1.0"
max_rinos_version = ""
dependencies = []
optional_dependencies = []
conflicts = []
provides = []
entry_points = []
flags = []
capabilities = []

[[files]]
path = "data/payload.bin"
source = "{source}"
'''

TRUSTED = b"trusted bytes from the opened source root\n"
ATTACKER = b"attacker-controlled replacement\n"
MAX_SOURCE = 32 * 1024 * 1024


def run_create(binary: Path, manifest: Path, output: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "create", "--manifest", str(manifest), "--output", str(output), "--json"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def write_fixture(root: Path, source: str, payload: bytes = TRUSTED) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / "package.toml"
    manifest.write_text(MANIFEST.format(source=source), encoding="utf-8")
    return manifest


def assert_payload(binary: Path, manifest: Path, output: Path, expected: bytes) -> None:
    result = run_create(binary, manifest, output)
    if result.returncode != 0:
        raise AssertionError(f"valid source was rejected:\n{result.stderr}")
    inspection = json.loads(result.stdout)
    entry = next(item for item in inspection["entries"] if item["path"] == "data/payload.bin")
    if entry["sha256"] != hashlib.sha256(expected).hexdigest():
        raise AssertionError("package payload did not come from the expected opened file")


def assert_rejected(binary: Path, manifest: Path, output: Path, label: str) -> None:
    result = run_create(binary, manifest, output)
    if result.returncode == 0:
        raise AssertionError(f"rinpack accepted {label}")
    if output.exists():
        raise AssertionError(f"rinpack published output after rejecting {label}")


def link_creation_is_unavailable(error: OSError) -> bool:
    return error.errno in (errno.EPERM, errno.EACCES, errno.ENOTSUP) or getattr(
        error, "winerror", None
    ) in (1, 5, 1314)


def create_directory_reparse(link: Path, target: Path) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", f'mklink /J "{link}" "{target}"'],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0 and link.is_dir()
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except OSError as error:
        if link_creation_is_unavailable(error):
            return False
        raise


def test_root_path_replacement(binary: Path, interposer: Path, base: Path) -> None:
    root = base / "root-swap"
    manifest = write_fixture(root, "payload.bin")
    (root / "payload.bin").write_bytes(TRUSTED)
    output = base / "root-swap.rpk"
    marker = base / "root-swap.marker"
    env = os.environ.copy()
    env["LD_PRELOAD"] = str(interposer)
    env["RINPACK_TEST_SOURCE_ROOT"] = str(root)
    env["RINPACK_TEST_SWAP_MARKER"] = str(marker)
    env["RINPACK_TEST_SWAP_COMPONENT"] = "payload.bin"
    result = run_create(binary, manifest, output, env)
    if not marker.exists():
        raise AssertionError("source-root replacement hook did not run")
    if result.returncode != 0:
        if output.exists():
            raise AssertionError("rinpack published an output after detecting root replacement")
        print("root path replacement: rejected without publishing a package")
        return
    inspection = json.loads(result.stdout)
    entry = next(item for item in inspection["entries"] if item["path"] == "data/payload.bin")
    if entry["sha256"] != hashlib.sha256(TRUSTED).hexdigest():
        raise AssertionError(
            "package followed or otherwise changed the source-root payload: "
            f"got {entry['sha256']}, trusted {hashlib.sha256(TRUSTED).hexdigest()}"
        )
    print("root path replacement: opened source remained bound to the original root")


def test_manifest_path_replacement(binary: Path, interposer: Path, base: Path) -> None:
    root = base / "manifest-swap"
    manifest = write_fixture(root, "payload.bin")
    (root / "payload.bin").write_bytes(TRUSTED)
    output = base / "manifest-swap.rpk"
    marker = base / "manifest-swap.marker"
    env = os.environ.copy()
    env["LD_PRELOAD"] = str(interposer)
    env["RINPACK_TEST_SOURCE_ROOT"] = str(root)
    env["RINPACK_TEST_SWAP_MARKER"] = str(marker)
    env["RINPACK_TEST_SWAP_COMPONENT"] = "package.toml"
    result = run_create(binary, manifest, output, env)
    if not marker.exists():
        raise AssertionError("manifest-root replacement hook did not run")
    if result.returncode != 0:
        if output.exists():
            raise AssertionError("rinpack published an output after detecting manifest-root replacement")
        print("manifest root replacement: rejected without publishing a package")
        return
    inspection = json.loads(result.stdout)
    if inspection["package_id"] != "org.rinos.toctou-test":
        raise AssertionError("package used a manifest opened through the replaced root pathname")
    entry = next(item for item in inspection["entries"] if item["path"] == "data/payload.bin")
    if entry["sha256"] != hashlib.sha256(TRUSTED).hexdigest():
        raise AssertionError("manifest race package did not contain the original source bytes")
    print("manifest root replacement: opened manifest remained bound to the original root")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--interposer", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    interposer = args.interposer.resolve() if args.interposer else None
    if not binary.is_file():
        raise SystemExit(f"rinpack executable does not exist: {binary}")
    build_root = Path(__file__).resolve().parents[4] / "build" / "rinpack-source-toctou" / "tmp"
    build_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="rinpack-source-toctou-", dir=build_root) as temporary:
        base = Path(temporary)
        valid = base / "valid"
        manifest = write_fixture(valid, "payload.bin")
        (valid / "payload.bin").write_bytes(TRUSTED)
        assert_payload(binary, manifest, base / "valid.rpk", TRUSTED)

        outside = base / "outside.bin"
        outside.write_bytes(ATTACKER)
        skipped: list[str] = []
        symlink_root = base / "symlink-source"
        symlink_manifest = write_fixture(symlink_root, "payload.bin")
        try:
            (symlink_root / "payload.bin").symlink_to(outside)
        except OSError as error:
            if not link_creation_is_unavailable(error):
                raise
            skipped.append("symlink source checks (filesystem does not permit symlink creation)")
        else:
            assert_rejected(binary, symlink_manifest, base / "symlink.rpk", "a source symlink")

        parent_root = base / "symlink-parent"
        parent_manifest = write_fixture(parent_root, "nested/payload.bin")
        (base / "payload.bin").write_bytes(ATTACKER)
        if not create_directory_reparse(parent_root / "nested", base):
            skipped.append("symlink-directory check (filesystem does not permit symlink creation)")
        else:
            assert_rejected(binary, parent_manifest, base / "symlink-parent.rpk", "a symlinked source directory")

        escape_root = base / "root-escape"
        escape_manifest = write_fixture(escape_root, "../outside.bin")
        assert_rejected(binary, escape_manifest, base / "escape.rpk", "a source path escaping the root")

        directory_root = base / "directory-source"
        directory_manifest = write_fixture(directory_root, "payload.bin")
        (directory_root / "payload.bin").mkdir()
        assert_rejected(binary, directory_manifest, base / "directory.rpk", "a directory source")

        if os.name != "nt":
            fifo_root = base / "fifo-source"
            fifo_manifest = write_fixture(fifo_root, "payload.bin")
            try:
                os.mkfifo(fifo_root / "payload.bin")
            except OSError as error:
                if not link_creation_is_unavailable(error):
                    raise
                skipped.append("FIFO check (filesystem does not support FIFO creation)")
            else:
                assert_rejected(binary, fifo_manifest, base / "fifo.rpk", "a FIFO source")

        large_root = base / "oversized-source"
        large_manifest = write_fixture(large_root, "payload.bin")
        with (large_root / "payload.bin").open("wb") as source:
            source.truncate(MAX_SOURCE + 1)
        assert_rejected(binary, large_manifest, base / "oversized.rpk", "a source over the size limit")

        if interposer is not None:
            test_root_path_replacement(binary, interposer, base)
            test_manifest_path_replacement(binary, interposer, base)

    for item in skipped:
        print(f"SKIP: {item}")
    print("rinpack source identity and TOCTOU acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
