import random
from pathlib import Path

# Inert text invented for this project. None of it is, or resembles, real malware.
MARKER = b"RULEBENCH-TEST-MARKER-7f3a9c1e-NOT-MALWARE"
NEAR_MISS = b"RULEBENCH-TEST-MARKER-7f3a9c1e-NOT-MALWARF"
SECOND = b"rulebench_beacon_label=demo-only"
LOREM = b"The quick brown fox jumps over the lazy dog. Nothing to see here.\n" * 8


def _noise(seed, n):
    return random.Random(seed).randbytes(n)


def build():
    return {
        "plain/marker.txt": b"synthetic fixture\n" + MARKER + b"\n",
        "plain/marker_and_label.txt": MARKER + b"\n" + SECOND + b"\n",
        "plain/label_only.txt": SECOND + b"\n",
        "plain/clean.txt": LOREM,
        "plain/near_miss.txt": b"decoy, one character off:\n" + NEAR_MISS + b"\n",
        "binary/marker_wide.bin": b"\xff\xfe" + MARKER.decode().encode("utf-16-le"),
        "binary/marker_in_noise.bin": _noise(1, 700) + MARKER + _noise(2, 300),
        "binary/clean_noise.bin": _noise(3, 2048),
        "binary/fake_mz_stub.bin": b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + MARKER,
        "encoded/marker_hex.txt": MARKER.hex().encode() + b"\n",
        "encoded/marker_upper.txt": MARKER.upper() + b"\n",
    }


def generate(dest):
    dest = Path(dest)
    files = build()
    for rel, data in files.items():
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return sorted(files)
