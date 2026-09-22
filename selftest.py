"""Parser self-test for tvsniff: feeds crafted Ethernet frames through
Sniffer.handle_frame and asserts the exact event sequence.

Run:  python3 selftest.py   (no privileges needed — no sockets are opened)
"""
import importlib.util
import json
import os
import socket
import struct
import sys
from importlib.machinery import SourceFileLoader

_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tvsniff")
_loader = SourceFileLoader("tvsniff", _path)
spec = importlib.util.spec_from_loader("tvsniff", _loader)
m = importlib.util.module_from_spec(spec)
_loader.exec_module(m)

TV, GW, SRV = "192.168.2.50", "192.168.2.1", "93.184.216.34"

events = []


class Out:
    def write(self, s):
        events.append(json.loads(s))

    def flush(self):
        pass


sn = m.Sniffer("lo", "192.168.2.0/24", Out(), {443, 8443}, 300, 16384)


def eth(payload):
    return (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
            + struct.pack("!H", 0x0800) + payload)


def ip4(src, dst, proto, payload):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0,
                       64, proto, 0, socket.inet_aton(src),
                       socket.inet_aton(dst)) + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 8192,
                       0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def client_hello(host):
    h = host.encode()
    entry = b"\x00" + struct.pack("!H", len(h)) + h
    name_list = struct.pack("!H", len(entry)) + entry
    sni_ext = struct.pack("!HH", 0x0000, len(name_list)) + name_list
    body = b"\x03\x03" + b"\x9c" * 32 + b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01"
    body += b"\x01\x00"
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def hello_no_sni():
    body = b"\x03\x03" + b"\x9c" * 32 + b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01"
    body += b"\x01\x00"
    ext = struct.pack("!HH", 0x0039, 4) + b"\x00\x00\x00\x00"  # padding only
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def dns_q(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return (struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + q
            + struct.pack("!HH", 1, 1))


def dns_a(name, ip):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return (struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 1, 0, 0) + q
            + struct.pack("!HH", 1, 1)
            + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton(ip))


# -- traffic ------------------------------------------------------------
# 1. TCP SYN TV -> server:443
sn.handle_frame(eth(ip4(TV, SRV, 6, tcp(40000, 443, 0x02))))
# 2. ClientHello split across two segments (SNI buffer must reassemble)
ch = client_hello("Example.ORG.")
sn.handle_frame(eth(ip4(TV, SRV, 6, tcp(40000, 443, 0x18, ch[:9]))))
sn.handle_frame(eth(ip4(TV, SRV, 6, tcp(40000, 443, 0x18, ch[9:]))))
# 3. SYN-ACK from server (reverse dir: same flow, must not log a new conn)
sn.handle_frame(eth(ip4(SRV, TV, 6, tcp(443, 40000, 0x12))))
# 4. DNS query TV -> relay
sn.handle_frame(eth(ip4(TV, GW, 17, udp(53535, 53, dns_q("api.tv.example")))))
# 5. DNS answer relay -> TV (compressed name pointer)
sn.handle_frame(eth(ip4(GW, TV, 17, udp(53, 53535, dns_a("api.tv.example", SRV)))))
# 6. RST teardown
sn.handle_frame(eth(ip4(TV, SRV, 6, tcp(40000, 443, 0x14))))
# 7. DHCP broadcast noise: ignored
sn.handle_frame(eth(ip4(TV, "255.255.255.255", 17, udp(68, 67, b"\x01" * 60))))
# 8. NTP flow
sn.handle_frame(eth(ip4(TV, "216.239.35.0", 17, udp(12345, 123, b"\x00" * 48))))

# -- assertions ---------------------------------------------------------
types = [e["type"] for e in events]
assert types == ["conn", "sni", "conn", "dns_q", "dns_a", "end", "conn"], types

e_conn, e_sni = events[0], events[1]
assert (e_conn["dir"], e_conn["proto"], e_conn["src"], e_conn["dst"],
        e_conn["dport"], e_conn["syn"]) == ("out", "tcp", TV, SRV, 443, True), e_conn
assert e_sni["name"] == "example.org", e_sni  # lowercased
assert events[3]["names"] == ["api.tv.example"], events[3]
assert events[4]["answers"] == [["api.tv.example", SRV]], events[4]

e_end = events[5]
assert (e_end["reason"], e_end["pkts"]) == ("rst", 5), e_end
# IP-level bytes: bare 40B packets (SYN, SYN-ACK, RST) + two segments carrying ch
assert e_end["bytes"] == 3 * 40 + (40 + 9) + (40 + len(ch) - 9), e_end["bytes"]
assert events[6]["dport"] == 123 and events[6]["proto"] == "udp", events[6]

# -- parser edge cases --------------------------------------------------
assert m.parse_sni(client_hello("x.io")[:7]) is None     # incomplete record
assert m.parse_sni(b"\x17\x03\x03\x00\x01\x00") is None  # not a handshake
assert m.parse_sni(hello_no_sni()) is None               # hello without SNI
assert m.parse_dns(b"\x01") == {"questions": [], "answers": []}  # truncated

print("SELFTEST PASS: %d events verified" % len(events))
