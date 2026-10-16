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
MAX_SOURCE = 64 * 1024 * 1024


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


def create_hardlink(source: Path, alias: Path) -> tuple[bool, str]:
    try:
        os.link(source, alias)
    except OSError as error:
        if link_creation_is_unavailable(error):
            return False, f"{type(error).__name__} errno={error.errno} winerror={getattr(error, 'winerror', None)}"
        raise
    return True, ""


def link_creation_is_unavailable(error: OSError) -> bool:
    return error.errno in (errno.EPERM, errno.EACCES, errno.ENOTSUP) or getattr(
        error, "winerror", None
    ) in (1, 5, 1314)


def create_directory_reparse(link: Path, target: Path) -> bool:
    if os.name == "nt":
        # cmd.exe's mklink /J incorrectly reports that local NTFS is required
        # for some redirected/local temp paths even when the target volume is
        # NTFS. PowerShell's Junction provider uses the same Windows reparse
        # point but works for those paths; keep cmd.exe as a compatibility
        # fallback for systems without the provider.
        env = os.environ.copy()
        env["RINPACK_TEST_JUNCTION_PATH"] = str(link)
        env["RINPACK_TEST_JUNCTION_TARGET"] = str(target)
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference = 'Stop'; New-Item -ItemType Junction "
                "-Path $env:RINPACK_TEST_JUNCTION_PATH "
                "-Target $env:RINPACK_TEST_JUNCTION_TARGET | Out-Null",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if result.returncode == 0 and link.is_dir():
            return True
        if link.exists():
            link.rmdir()
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


def test_hardlink_aliases(binary: Path, base: Path, required_skipped: list[str]) -> None:
    source_root = base / "hardlink-source"
    source_manifest = write_fixture(source_root, "payload.bin")
    source = source_root / "payload.bin"
    source.write_bytes(TRUSTED)
    source_hardlink_created, source_hardlink_error = create_hardlink(
        source, base / "payload-source.alias",
    )
    if source_hardlink_created:
        assert_rejected(
            binary, source_manifest, base / "hardlink-source.rpk",
            "a source file with a hardlink alias outside the manifest root",
        )
    else:
        required_skipped.append(f"source hardlink alias check (filesystem does not permit hardlinks: {source_hardlink_error})")

    manifest_root = base / "hardlink-manifest"
    manifest = write_fixture(manifest_root, "payload.bin")
    (manifest_root / "payload.bin").write_bytes(TRUSTED)
    manifest_hardlink_created, manifest_hardlink_error = create_hardlink(
        manifest, base / "package-manifest.alias",
    )
    if manifest_hardlink_created:
        assert_rejected(
            binary, manifest, base / "hardlink-manifest.rpk",
            "a manifest with a hardlink alias outside its source root",
        )
    else:
        required_skipped.append(f"manifest hardlink alias check (filesystem does not permit hardlinks: {manifest_hardlink_error})")


def test_hardlink_added_while_reading(
    binary: Path, interposer: Path, base: Path, component: str,
    label: str, required_skipped: list[str],
) -> None:
    root = base / f"hardlink-race-{component.replace('.', '-')}"
    manifest = write_fixture(root, "payload.bin")
    (root / "payload.bin").write_bytes(TRUSTED)
    output = base / f"hardlink-race-{component.replace('.', '-')}.rpk"
    marker = base / f"hardlink-race-{component.replace('.', '-')}.marker"
    alias = base / f"hardlink-race-{component.replace('.', '-')}.alias"
    env = os.environ.copy()
    env["LD_PRELOAD"] = str(interposer)
    env["RINPACK_TEST_HARDLINK_COMPONENT"] = component
    env["RINPACK_TEST_HARDLINK_ROOT"] = str(root)
    env["RINPACK_TEST_HARDLINK_ALIAS"] = str(alias)
    env["RINPACK_TEST_HARDLINK_MARKER"] = str(marker)
    result = run_create(binary, manifest, output, env)
    if not marker.exists():
        raise AssertionError(
            f"{label} hardlink race hook did not run (stderr={result.stderr.strip()!r})"
        )
    outcome = marker.read_text(encoding="ascii").strip()
    if outcome.startswith("error="):
        error_number = int(outcome.split("=", 1)[1])
        unavailable = {
            errno.EPERM, errno.EACCES, errno.EXDEV,
            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        }
        if error_number in unavailable:
            required_skipped.append(
                f"{label} hardlink race (filesystem does not permit hardlinks: errno={error_number})"
            )
            return
        raise AssertionError(f"{label} hardlink race injection failed with errno {error_number}")
    if outcome != "created":
        raise AssertionError(f"{label} hardlink race hook returned an unknown outcome: {outcome!r}")
    if not alias.exists():
        raise AssertionError(f"{label} hardlink race marker was written without creating its alias")
    if result.returncode == 0 or output.exists():
        source_links = (root / "payload.bin").stat().st_nlink
        raise AssertionError(
            f"rinpack published a package after a hardlink appeared while reading {label} "
            f"(source links={source_links}, marker={outcome!r}, stderr={result.stderr.strip()!r})"
        )
    print(f"{label} hardlink added while reading: rejected without publishing a package")


def test_component_symlink_swap(
    binary: Path, interposer: Path, base: Path, source: str,
    component: str, attacker_target: Path, label: str,
    required_skipped: list[str],
) -> None:
    root = base / f"symlink-race-{label}"
    manifest = write_fixture(root, source)
    if source == "payload.bin":
        (root / source).write_bytes(TRUSTED)
    else:
        nested = root / "nested"
        nested.mkdir()
        (nested / "payload.bin").write_bytes(TRUSTED)
    output = base / f"symlink-race-{label}.rpk"
    marker = base / f"symlink-race-{label}.marker"
    env = os.environ.copy()
    env["LD_PRELOAD"] = str(interposer)
    env["RINPACK_TEST_SWAP_STYLE"] = "component-symlink"
    env["RINPACK_TEST_SWAP_COMPONENT"] = component
    env["RINPACK_TEST_SWAP_TARGET"] = str(attacker_target)
    env["RINPACK_TEST_SWAP_MARKER"] = str(marker)
    result = run_create(binary, manifest, output, env)
    if not marker.exists():
        raise AssertionError(f"{label} component symlink race hook did not run")
    outcome = marker.read_text(encoding="ascii").strip()
    if outcome.startswith("error="):
        error_number = int(outcome.split("=", 1)[1])
        unavailable = {
            errno.EPERM, errno.EACCES,
            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        }
        if error_number in unavailable:
            required_skipped.append(
                f"{label} symlink swap (filesystem does not permit symlinks: errno={error_number})"
            )
            return
        raise AssertionError(f"{label} symlink race injection failed with errno {error_number}")
    if outcome != "created":
        raise AssertionError(f"{label} symlink race hook returned an unknown outcome: {outcome!r}")
    if result.returncode == 0 or output.exists():
        raise AssertionError(f"rinpack followed a swapped symlink for {label}")
    print(f"{label} component changed to a symlink while opening: rejected without publishing a package")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--interposer", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    interposer = args.interposer.resolve() if args.interposer else None
    if not binary.is_file():
        raise SystemExit(f"rinpack executable does not exist: {binary}")
    default_build_root = Path(__file__).resolve().parents[4] / "build" / "rinpack-source-toctou" / "tmp"
    build_root = Path(os.environ.get("RINPACK_TEST_SCRATCH_ROOT", default_build_root))
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
        required_skipped: list[str] = []
        symlink_root = base / "symlink-source"
        symlink_manifest = write_fixture(symlink_root, "payload.bin")
        try:
            (symlink_root / "payload.bin").symlink_to(outside)
        except OSError as error:
            if not link_creation_is_unavailable(error):
                raise
            required_skipped.append("symlink source check (filesystem does not permit symlink creation)")
        else:
            assert_rejected(binary, symlink_manifest, base / "symlink.rpk", "a source symlink")

        parent_root = base / "symlink-parent"
        parent_manifest = write_fixture(parent_root, "nested/payload.bin")
        (base / "payload.bin").write_bytes(ATTACKER)
        if not create_directory_reparse(parent_root / "nested", base):
            required_skipped.append("symlink-directory check (filesystem does not permit reparse points)")
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

        test_hardlink_aliases(binary, base, required_skipped)

        if interposer is not None:
            test_root_path_replacement(binary, interposer, base)
            test_manifest_path_replacement(binary, interposer, base)
            test_hardlink_added_while_reading(
                binary, interposer, base, "payload.bin", "source", required_skipped,
            )
            test_hardlink_added_while_reading(
                binary, interposer, base, "package.toml", "manifest", required_skipped,
            )
            attacker_directory = base / "attacker-directory"
            attacker_directory.mkdir()
            (attacker_directory / "payload.bin").write_bytes(ATTACKER)
            test_component_symlink_swap(
                binary, interposer, base, "payload.bin", "payload.bin",
                outside, "source-file", required_skipped,
            )
            test_component_symlink_swap(
                binary, interposer, base, "nested/payload.bin", "nested",
                attacker_directory, "source-directory", required_skipped,
            )

    for item in skipped:
        print(f"SKIP: {item}")
    for item in required_skipped:
        print(f"BLOCKED: {item}")
    if required_skipped:
        print("rinpack source identity and TOCTOU acceptance: INCOMPLETE")
        return 2
    print("rinpack source identity and TOCTOU acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
