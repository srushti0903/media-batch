"""Unpack the encrypted bundle."""
import hashlib, hmac, io, re, tarfile
from pathlib import Path

k = hashlib.sha256(re.search(r"^KATHA_KEY=(\S+)", Path(".env").read_text(), re.M).group(1).encode()).digest()


def dec(blob):
    assert blob[:4] == b"LTV1"
    nonce, mac, ct = blob[4:20], blob[20:52], blob[52:]
    assert hmac.compare_digest(mac, hmac.new(k, nonce + ct, hashlib.sha256).digest())
    ks = b"".join(hashlib.sha256(k + nonce + i.to_bytes(8, "big")).digest() for i in range((len(ct) + 31) // 32))[:len(ct)]
    return (int.from_bytes(ct, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(ct), "big")


raw, out, i = Path("bundle.enc").read_bytes(), io.BytesIO(), 0
while i < len(raw):
    n = int.from_bytes(raw[i:i + 8], "big"); out.write(dec(raw[i + 8:i + 8 + n])); i += 8 + n
with tarfile.open(fileobj=io.BytesIO(out.getvalue())) as t:
    t.extractall(".")
print("ok")
