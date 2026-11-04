#!/usr/bin/env python3
"""Test every publicly-known Zyxel serial->password variant against our real
(serial, supervisor-password) pairs. Our own clean port; validated against the
boginw/zyxel-vmg8825-keygen published test vectors before trusting any result.

Goal: does ANY documented algorithm reproduce our EX3301-T0 passwords?
"""
import hashlib
import json
import os
from pathlib import Path


def load_private_pairs():
    """Load serial/password vectors from an explicit file outside this repo."""
    source = os.environ.get("WEAKND_KEYGEN_PAIRS_FILE")
    if not source:
        print("private device vectors not supplied; set WEAKND_KEYGEN_PAIRS_FILE to test them")
        return {}
    path = Path(source).expanduser().resolve()
    repository = Path(__file__).resolve().parents[1]
    try:
        path.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ValueError("private keygen vectors must be stored outside the repository")
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not all(
            isinstance(serial, str) and isinstance(password, str)
            for serial, password in data.items()):
        raise ValueError("private vector file must be a JSON serial-to-password object")
    return data

def md5d(s): return hashlib.md5(s.encode("ascii")).digest()
def hx(b):
    s = format(b, "x"); return s + s if len(s) == 1 else s

def double_hash(inp, size):
    m = md5d(inp); r1 = "".join(hx(m[i]) for i in range(16))
    m = hashlib.md5(r1.encode("ascii")).digest(); r2 = "".join(hx(m[i]) for i in range(16))
    r3 = bytearray(size)
    for i in range(size): r3[i] = ord(r2[i * 3])
    return r3

# ---- Method2 / Method3 (already validated in weaknd.zyxel_keygen) ----
def method2(serial, size=8): return double_hash(serial, size).decode("ascii")

VAL = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789ABCDEF"
def mod3(seed):
    r4 = [0]*16; f0=f1=f2=0
    while f0==0 or f1==0 or f2==0:
        f0=f1=f2=0; p=1; seed+=1
        for i in range(10):
            r4[i]=seed%(p*3)//p
            if r4[i]==1: f1+=1
            elif r4[i]==2: f2+=1
            else: f0+=1
            p<<=1
    return seed,r4
def method3(serial, size=10):
    r=bytearray(double_hash(serial,size).decode("ascii").upper(),"ascii")
    m=md5d(serial); n=(m[1]<<8)+m[2]; n,r4=mod3(n)
    for i in range(size):
        c=r[i]
        if r4[i]==1:
            r[i]=(c%26)+65
            for j in range(2):
                if r[i]==b"IO"[j]: r[i]=ord(VAL[0x8+((n+j)%0x18)]); break
        elif r4[i]==2:
            r[i]=(c%26)+97
            for j in range(2):
                if r[i]==b"lo"[j]: r[i]=ord(VAL[0x20+((n+j)%0x18)]); break
        else:
            r[i]=(c%10)+48
            for j in range(2):
                if r[i]==b"10"[j]:
                    var=((n+j)>>0x1f)>>0x1d; r[i]=ord(VAL[((n+j+var)&7)-var]); break
    return r[:size].decode("ascii")

# ---- ConfigLengthOld (method 1/2/3) ----
V1=b"3479ACHJKMNPRTUVWXY"; V2=b"ACHJKMNPRTUVWXY"; V3=b"bdfhjkmprstuvwxyz"
V4=b"3456789ABCDEFGHJKLMNPQRTUXYSVW"; V5=b"3478ABCDEFGHJKLMNPQRTUVWXY"
def clo(serial, inputKey, size, method=1):
    if not inputKey: return "1234"
    m=md5d(serial)
    m=hashlib.md5((inputKey+"Account_Password").encode("ascii")+m).digest()
    n=(m[3]<<8)+m[2]; mult=2 if method==1 else 3
    r1=[0]*16; p=1
    for i in range(size): r1[i]=(n%(mult*p))//p; p*=2
    r2=bytearray(17); off=0
    for i in range(size):
        if r1[i]==1: ch=(m[i]%0x1a)+65
        elif r1[i]==2: ch=(m[i]%0x1a)+97
        else:
            mb=m[i]; inter=(mb*0xcccccccd)>>32>>3<<1
            ch=mb-(((inter&0xff)+((inter<<2)&0xff))&0xff)+48
        r2[off]=ch&0xff; off+=1
        if method==2:
            for j,k in enumerate(b"125680"):
                if r2[i]==k:
                    inter=((n+j)>>0x1f)>>0x1e; r2[i]=V1[((n+j+inter)&3)-inter]; break
            for j,k in enumerate(b"BDEFGILOQSZ"):
                if r2[i]==k: r2[i]=V2[(n+j)%0xf]; break
            for j,k in enumerate(b"acegilnoq"):
                if r2[i]==k: r2[i]=V3[(n+j)%0x11]; break
        elif method==3:
            for j,k in enumerate(b"120IOZoliz"):
                if r2[i]==k: r2[i]=V4[(n+j)%0x1e]; break
        else:
            for j,k in enumerate(b"125690IOSZ"):
                if r2[i]==k: r2[i]=V5[(n+j)%0x1a]; break
    return bytes(r2[:size]).decode("ascii","replace")

# ---------------- validation against published vectors ----------------
VEC = {
    "S200Y20000000": {
        ("method2",8):"46901a90", ("method3",10):"A4FwX57859",
        ("clo1",8):"8YD7XXY7", ("clo2",8):"Nh777V9N", ("clo3",8):"88D78CBN",
    },
}
def getv(name, serial, size):
    if name=="method2": return method2(serial,size)
    if name=="method3": return method3(serial,size)
    if name=="clo1": return clo(serial,"inputKey",size,1)
    if name=="clo2": return clo(serial,"inputKey",size,2)
    if name=="clo3": return clo(serial,"inputKey",size,3)

print("=== validation vs published vectors ===")
allok=True
for serial,exp in VEC.items():
    for (name,size),want in exp.items():
        got=getv(name,serial,size); ok=got==want; allok&=ok
        print(f"  [{'OK ' if ok else 'FAIL'}] {name}({size}) {serial}: {got} (want {want})")
print("PORT VALID" if allok else "PORT BROKEN — do not trust results below")

print("\n=== our real devices: any match? ===")
PAIRS=load_private_pairs()
names=[("method2",8),("method2",10),("method3",10),("method3",8),
       ("clo1",8),("clo1",10),("clo2",8),("clo2",10),("clo3",8),("clo3",10)]
for serial,real in PAIRS.items():
    hits=[f"{n}({s})" for n,s in names if getv(n,serial,s)==real]
    print(f"{serial} real=[REDACTED] -> "
          f"{'MATCH via '+','.join(hits) if hits else 'no public variant matches'}")
