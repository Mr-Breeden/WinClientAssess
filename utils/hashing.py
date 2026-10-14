from __future__ import annotations

import hashlib


def file_hashes(path, algorithms=("sha256", "sha1", "md5"), chunk_size=1024 * 1024, prefix_bytes=0):
    """Calculate multiple hashes in one pass and optionally retain a small leading byte window."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    prefix = bytearray()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
            if prefix_bytes and len(prefix) < prefix_bytes:
                needed = prefix_bytes - len(prefix)
                prefix.extend(chunk[:needed])
    result = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    if prefix_bytes:
        result["prefix_bytes"] = bytes(prefix)
    return result
