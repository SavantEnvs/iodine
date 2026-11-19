#!/usr/bin/env python3
"""Regenerate the committed seed corpora under mayhem/<target>/testsuite/.

Not run by build.sh: the seeds are committed. Run from the repo root:
    python3 -I mayhem/tools/gen_seeds.py
The tunnel protocol details follow src/client.c (send_version, send_login, send_packet ->
build_hostname) and src/server.c; the harnesses mock entropy to all-zero bytes, so the server's
login seed is 0 and the login hash is md5 of the 32-byte password buffer.
"""
import hashlib
import os
import struct

TOP = "test.iodine.code"
PASSWORD = b"testpass".ljust(32, b"\0")
PROTOCOL_VERSION = 0x00000502
T_A, T_NS, T_CNAME, T_SOA, T_NULL, T_MX, T_TXT, T_AAAA, T_SRV = 1, 2, 5, 6, 10, 15, 16, 28, 33
B32 = "abcdefghijklmnopqrstuvwxyz012345"
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def b32(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(B32[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def hostname(cmd: str, data: bytes) -> str:
    enc = b32(data)
    enc = ".".join(enc[i:i + 57] for i in range(0, len(enc), 57))
    return f"{cmd}{enc}.{TOP}"


def qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def query(qid: int, name: str, qtype: int) -> bytes:
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack(">HH", qtype, 1)


def answer(qid: int, name: str, qtype: int, rdata: bytes) -> bytes:
    hdr = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    q = qname(name) + struct.pack(">HH", qtype, 1)
    rr = struct.pack(">HHHIH", 0xC00C, qtype, 1, 0, len(rdata)) + rdata
    return hdr + q + rr


def txt(data: bytes) -> bytes:
    out = b""
    for i in range(0, len(data), 255):
        chunk = data[i:i + 255]
        out += bytes([len(chunk)]) + chunk
    return out


def rec(kind: int, data: bytes) -> bytes:
    return bytes([kind]) + struct.pack(">H", len(data)) + data


def write(target: str, name: str, data: bytes) -> None:
    d = os.path.join(ROOT, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def login_hash(seed: int) -> bytes:
    words = struct.unpack(">8i", PASSWORD)
    temp = struct.pack(">8i", *[w ^ seed for w in words])
    return hashlib.md5(temp).digest()


# ---- server-side queries -------------------------------------------------------------------
v = query(1, hostname("v", struct.pack(">I", PROTOCOL_VERSION) + b"\0\0"), T_NULL)
login = query(2, hostname("l", b"\0" + login_hash(0) + b"\0\1"), T_NULL)
ipreq = query(3, f"i{B32[0]}aab.{TOP}", T_NULL)
opt = query(4, f"o{B32[0]}raac.{TOP}", T_NULL)
ping = query(5, hostname("p", b"\0\0\0\2"), T_NULL)
data = query(6, f"0aaaa{b32(bytes(range(40)))}.{TOP}", T_NULL)
ns = query(7, TOP, T_NS)
a_ns = query(8, "ns." + TOP, T_A)
aaaa_www = query(9, "www." + TOP, T_AAAA)
fwd = query(10, "www.example.com", T_A)
raw_login = bytes([0x10, 0xD1, 0x9E, 0x10]) + login_hash(1)
fwd_answer = answer(10, "www.example.com", T_A, bytes([93, 184, 216, 34]))

server = {
    "version": [v],
    "login": [v, login],
    "login_ip_options": [v, login, ipreq, opt],
    "login_ping_data": [v, login, ping, data],
    "raw_login": [v, login, raw_login],
    "ns_a_aaaa": [ns, a_ns, aaaa_www],
}
for name, pkts in server.items():
    write("server", name, b"".join(rec(0, p) for p in pkts))
write("server", "forward", rec(0, fwd) + rec(1, fwd_answer))
for i, p in enumerate([v, login, ipreq, opt, ping, data, ns, a_ns, aaaa_www, fwd]):
    write("dns_query", f"query{i:02d}", p)

# ---- client-side answers -------------------------------------------------------------------
vack = b"VACK" + struct.pack(">I", 0) + b"\0"
lok = b"10.0.0.1-10.0.0.2-1130-27"
vname = hostname("v", struct.pack(">I", PROTOCOL_VERSION) + b"\0\0")
lname = hostname("l", b"\0" + login_hash(0) + b"\0\1")
r_v_null = answer(0, vname, T_NULL, vack)
r_l_null = answer(0, lname, T_NULL, lok)
r_v_txt = answer(0, vname, T_TXT, txt(b"t" + b32(vack).encode()))
r_l_txt = answer(0, lname, T_TXT, txt(b"t" + b32(lok).encode()))
r_v_cname = answer(0, vname, T_CNAME, qname("h" + b32(vack) + ".xy"))
r_y = answer(0, f"yaaaa.{TOP}", T_NULL, b"\0\0\0\0\377\377\377\377UUUU\252\252\252\252")
r_edns = answer(0, f"yaaaa.{TOP}", T_NULL, b"\0")

# config byte: bits 0-2 qtype (0 NULL, 6 TXT, 2 CNAME)
write("client", "null_handshake", bytes([0]) + rec(0, r_v_null) + rec(0, r_l_null) + rec(0, r_edns) + rec(0, r_y))
write("client", "txt_handshake", bytes([6]) + rec(0, r_v_txt) + rec(0, r_l_txt))
write("client", "cname_version", bytes([2]) + rec(0, r_v_cname))
write("client", "raw_mode", bytes([8]) + rec(0, r_v_null) + rec(0, r_l_null) + rec(2, b"") + rec(0, r_edns))
for i, p in enumerate([r_v_null, r_l_null, r_v_txt, r_l_txt, r_v_cname, r_y, fwd_answer]):
    write("dns_answer", f"answer{i:02d}", p)

# ---- codecs --------------------------------------------------------------------------------
for i, (sel, payload) in enumerate([
        (0x00, b32(b"hello iodine").encode()),
        (0x41, b"aGVsbG8gaW9kaW5l"),
        (0x63, bytes(range(256))),
        (0x24, b"\x00\xff" * 40),
        (0x52, b"Hello.World.0123456789"),
        (0x10, b"habcdefgh.xy"),
]):
    write("encoding", f"codec{i:02d}", bytes([sel, 0xFF]) + payload)
