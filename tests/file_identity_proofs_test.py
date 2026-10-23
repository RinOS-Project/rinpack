#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check rinpack's RFIM v2 executable page-proof output independently."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


ROOT = Path(__file__).resolve().parents[4]
PKG_HEADER_SIZE = 256
PKG_ENTRY_SIZE = 224
PKG_PATH_SIZE = 192
RFIM_MAGIC = 0x4D494652
RFIM_VERSION_PAGE_PROOFS = 2
RFIM_HEADER_SIZE = 32
RFIM_ENTRY_V2_SIZE = 316
PAGE_SIZE = 4096
RIN_IMAGE_MAGIC = 0x004E4952
RIN_IMAGE_VERSION_3 = 0x00030000
RIN_IMAGE_EXECUTABLE = 1


def fail(message: str) -> None:
    raise AssertionError(message)


def leaf_digest(index: int, chunk: bytes | None) -> bytes:
    if chunk is None:
        size = 0
        content_digest = bytes(32)
    else:
        size = len(chunk)
        content_digest = hashlib.sha256(chunk).digest()
    return hashlib.sha256(
        b"RinOS-RDM3-leaf\0" + struct.pack("<III", index, 0, size)
        + content_digest
    ).digest()


def parent_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"RinOS-RDM3-node\0" + left + right).digest()


def proof_depth(page_count: int) -> int:
    capacity = 1
    depth = 0
    while capacity < page_count:
        capacity <<= 1
        depth += 1
    return depth


def make_expected_tree(image: bytes) -> tuple[bytes, list[bytes]]:
    pages = [image[offset:offset + PAGE_SIZE]
             for offset in range(0, len(image), PAGE_SIZE)]
    capacity = 1 << proof_depth(len(pages))
    level = [leaf_digest(index, pages[index] if index < len(pages) else None)
             for index in range(capacity)]
    proofs = [[] for _ in pages]
    positions = list(range(len(pages)))
    while len(level) > 1:
        for page, position in enumerate(positions):
            proofs[page].append(level[position ^ 1])
        level = [parent_digest(level[index], level[index + 1])
                 for index in range(0, len(level), 2)]
        positions = [position >> 1 for position in positions]
    return level[0], [b"".join(proof) for proof in proofs]


def verify_page(index: int, page: bytes, proof: bytes, depth: int,
                page_count: int, root: bytes) -> bool:
    digest = leaf_digest(index, page)
    for level in range(depth):
        sibling = proof[level * 32:(level + 1) * 32]
        if len(sibling) != 32:
            return False
        digest = (parent_digest(sibling, digest)
                  if ((index >> level) & 1)
                  else parent_digest(digest, sibling))
    return page_count > index and digest == root


def make_executable() -> bytes:
    image = bytearray(PAGE_SIZE * 2 + 137)
    struct.pack_into("<I", image, 0, RIN_IMAGE_MAGIC)
    struct.pack_into("<I", image, 4, RIN_IMAGE_VERSION_3)
    struct.pack_into("<H", image, 8, 256)
    struct.pack_into("<H", image, 10, 1)  # x86_64
    struct.pack_into("<H", image, 12, 1)  # ABI major
    struct.pack_into("<H", image, 14, 4)  # ABI minor
    struct.pack_into("<I", image, 16, RIN_IMAGE_EXECUTABLE)
    # RinHeaderV3.image_size is a 64-bit field at byte offset 44. Its ABI
    # fields at offset 12 deliberately make a mistaken get32(offset 12) fail.
    struct.pack_into("<Q", image, 44, len(image))
    image[116:148] = bytes(range(1, 33))
    for offset in range(256, len(image)):
        image[offset] = (offset * 131 + 17) & 0xFF
    return bytes(image)


def package_entries(image: bytes) -> dict[str, bytes]:
    if len(image) < PKG_HEADER_SIZE:
        fail("package is truncated")
    file_count = struct.unpack_from("<I", image, 168)[0]
    data_offset = PKG_HEADER_SIZE + file_count * PKG_ENTRY_SIZE
    if data_offset > len(image):
        fail("package entry table is truncated")
    entries: dict[str, bytes] = {}
    for index in range(file_count):
        entry = image[PKG_HEADER_SIZE + index * PKG_ENTRY_SIZE:
                      PKG_HEADER_SIZE + (index + 1) * PKG_ENTRY_SIZE]
        path = entry[:PKG_PATH_SIZE].split(b"\0", 1)[0].decode("utf-8")
        offset, size, checksum, flags = struct.unpack_from("<IIIH", entry, 192)
        content = image[data_offset + offset:data_offset + offset + size]
        if len(content) != size or zlib.crc32(content) & 0xFFFFFFFF != checksum:
            fail(f"package entry {path!r} has an invalid range or checksum")
        if path in entries:
            fail(f"duplicate package path {path!r}")
        if path.startswith(".rinpkg/") and flags != 1:
            fail(f"reserved metadata entry {path!r} is not marked as metadata")
        entries[path] = content
    return entries


def verify_rfim(package: bytes, executable: bytes) -> None:
    entries = package_entries(package)
    metadata = entries.get(".rinpkg/file-identities.rfim")
    if metadata is None or len(metadata) < RFIM_HEADER_SIZE:
        fail("package does not contain a complete RFIM")
    magic, version, header_size, count, entry_size, checksum, flags = \
        struct.unpack_from("<IHHIIII", metadata, 0)
    if (magic, version, header_size, entry_size, flags) != (
        RFIM_MAGIC, RFIM_VERSION_PAGE_PROOFS, RFIM_HEADER_SIZE,
        RFIM_ENTRY_V2_SIZE, 0,
    ):
        fail("rinpack emitted an unexpected RFIM v2 header")
    if len(metadata) < RFIM_HEADER_SIZE + count * entry_size:
        fail("RFIM fixed entries are truncated")
    checked = bytearray(metadata)
    checked[16:20] = bytes(4)
    if zlib.crc32(checked) & 0xFFFFFFFF != checksum:
        fail("RFIM checksum does not cover the proof table")

    executable_record = None
    for index in range(count):
        record = metadata[RFIM_HEADER_SIZE + index * entry_size:
                          RFIM_HEADER_SIZE + (index + 1) * entry_size]
        path = record[:PKG_PATH_SIZE].split(b"\0", 1)[0].decode("utf-8")
        file_size = struct.unpack_from("<Q", record, 192)[0]
        file_digest = record[200:232]
        image_id = record[232:264]
        page_size, page_count, depth, proof_offset, proof_size = \
            struct.unpack_from("<IIIII", record, 264)
        root = record[284:316]
        if path == "bin/main.rin":
            executable_record = (
                file_size, file_digest, image_id, page_size, page_count,
                depth, proof_offset, proof_size, root,
            )
        elif any(record[232:]):
            fail(f"non-executable identity {path!r} has proof fields")
    if executable_record is None:
        fail("RFIM omitted the RIN v3 executable")
    (file_size, file_digest, image_id, page_size, page_count, depth,
     proof_offset, proof_size, root) = executable_record
    expected_root, expected_proofs = make_expected_tree(executable)
    pages = [executable[offset:offset + PAGE_SIZE]
             for offset in range(0, len(executable), PAGE_SIZE)]
    expected_depth = proof_depth(len(pages))
    expected_size = len(pages) * expected_depth * 32
    if file_size != len(executable) or file_digest != hashlib.sha256(executable).digest():
        fail("RFIM executable file identity does not match the package payload")
    if image_id != executable[116:148]:
        fail("RFIM executable content identity does not match RinHeaderV3")
    if (page_size, page_count, depth, proof_size) != (
        PAGE_SIZE, len(pages), expected_depth, expected_size,
    ):
        fail("RFIM executable page geometry is invalid")
    if proof_offset != RFIM_HEADER_SIZE + count * entry_size:
        fail("RFIM proof table is not contiguous after fixed-size records")
    if proof_offset + proof_size != len(metadata):
        fail("RFIM proof table has an invalid range or trailing bytes")
    if root != expected_root:
        fail("RFIM Merkle root disagrees with the RDM3 page tree")
    for index, page in enumerate(pages):
        actual = metadata[proof_offset + index * depth * 32:
                          proof_offset + (index + 1) * depth * 32]
        if actual != expected_proofs[index] or not verify_page(
            index, page, actual, depth, page_count, root,
        ):
            fail(f"RFIM page {index} proof does not authenticate its bytes")

    corrupted_page = bytearray(pages[-1])
    corrupted_page[0] ^= 1
    if verify_page(page_count - 1, bytes(corrupted_page),
                   expected_proofs[-1], depth, page_count, root):
        fail("a page mutation was accepted by its signed proof")
    corrupted_proof = bytearray(expected_proofs[0])
    corrupted_proof[0] ^= 1
    if verify_page(0, pages[0], bytes(corrupted_proof),
                   depth, page_count, root):
        fail("a corrupted sibling proof was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        fail(f"rinpack test binary does not exist: {binary}")
    build_root = ROOT / "build" / "rinpack-file-identity-proofs"
    build_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fixture-", dir=build_root) as temporary:
        directory = Path(temporary)
        (directory / "main.rin").write_bytes(make_executable())
        (directory / "readme.txt").write_bytes(b"non-executable payload\n")
        private_key = directory / "publisher.pem"
        public_key = directory / "publisher.der"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
             "rsa_keygen_bits:2048", "-out", str(private_key)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30,
        )
        with public_key.open("wb") as stream:
            subprocess.run(
                ["openssl", "rsa", "-in", str(private_key),
                 "-RSAPublicKey_out", "-outform", "DER"],
                check=True, stdout=stream, stderr=subprocess.PIPE, timeout=30,
            )
        manifest = directory / "package.toml"
        manifest.write_text(
            """[package]
package_id = "org.rinos.rfim-proof-test"
display_name = "RFIM Proof Test"
version = "1.0.0"
architecture = "x86_64"
package_type = "application"
description = "RIN v3 page proof test."
license = "MIT"
homepage = "https://example.invalid/rfim-proof-test"
min_rinos_version = "1.0"
max_rinos_version = ""
dependencies = []
optional_dependencies = []
conflicts = []
provides = []
entry_points = [{name = "main", path = "bin/main.rin"}]
flags = []
capabilities = []

[[files]]
path = "bin/main.rin"
source = "main.rin"

[[files]]
path = "share/readme.txt"
source = "readme.txt"
""",
            encoding="utf-8",
        )
        package_path = directory / "rfim-proof.rpk"
        completed = subprocess.run(
            [str(binary), "create", "--manifest", str(manifest),
             "--output", str(package_path), "--sign-key", str(private_key),
             "--public-key", str(public_key), "--publisher-generation", "1",
             "--json"],
            cwd=ROOT, check=False, capture_output=True, text=True, timeout=30,
        )
        if completed.returncode != 0:
            fail(f"rinpack rejected a valid RIN v3 header:\n{completed.stderr}")
        verify_rfim(package_path.read_bytes(), (directory / "main.rin").read_bytes())
    print("rinpack RFIM v2 executable page proofs passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
