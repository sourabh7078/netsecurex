"""
NetSecureX - UDP service probing (SNMP)

UDP has no handshake, so a plain "is it open?" check is unreliable: a closed
UDP port usually gives no answer at all. NetSecureX therefore uses a
protocol-specific probe. For SNMP (UDP 161) it sends a version-1 GetRequest
for the system description (sysDescr.0) with a community string, and treats
any reply as evidence that the service is listening.

Scope: only SNMP is probed. Other UDP services are not detected.

Environment variables:
    NSX_UDP_SCAN        "true"/"false" to enable or disable the probe. Default: true
    NSX_SNMP_COMMUNITY  Community string to try. Default: public
    NSX_UDP_TIMEOUT     Seconds to wait for a reply. Default: 1.0
"""

import os
import socket
import struct

SNMP_PORT = 161
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"


def _env_bool(name, default=True):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


UDP_SCAN_ENABLED = _env_bool("NSX_UDP_SCAN", default=True)
SNMP_COMMUNITY = os.environ.get("NSX_SNMP_COMMUNITY", "public")
UDP_TIMEOUT = float(os.environ.get("NSX_UDP_TIMEOUT", "1.0"))
# Which probes run, in order. Each name matches a probe below.
ENABLED_PROBES = [p.strip().lower() for p in os.environ.get("NSX_UDP_PROBES", "snmp,dns,ntp").split(",") if p.strip()]


# --------------------------------------------------------------- BER encoding
def _length(n):
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, content):
    return bytes([tag]) + _length(len(content)) + content


def _integer(n):
    return _tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big"))


def _base128(v):
    out = [v & 0x7F]
    v >>= 7
    while v:
        out.insert(0, (v & 0x7F) | 0x80)
        v >>= 7
    return bytes(out)


def encode_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = _base128(40 * parts[0] + parts[1])
    for p in parts[2:]:
        body += _base128(p)
    return _tlv(0x06, body)


def build_snmp_get_request(community=SNMP_COMMUNITY, oid=SYS_DESCR_OID, request_id=1):
    """Return the bytes of an SNMP v1 GetRequest for one OID."""
    varbind = _tlv(0x30, encode_oid(oid) + b"\x05\x00")       # OID, NULL value
    varbind_list = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _integer(request_id) + _integer(0) + _integer(0) + varbind_list)
    return _tlv(0x30, _integer(0) + _tlv(0x04, community.encode("ascii")) + pdu)


# --------------------------------------------------------------- BER decoding
def _read_tlv(data, pos):
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise ValueError("truncated BER element")
    return tag, data[pos:end], end


def _children(content):
    items, pos = [], 0
    while pos < len(content):
        tag, value, pos = _read_tlv(content, pos)
        items.append((tag, value))
    return items


def parse_snmp_response(data):
    """Parse an SNMP GetResponse. Returns a dict with version, community and
    sysdescr, or None if the bytes are not a well-formed GetResponse."""
    try:
        tag, msg, _ = _read_tlv(data, 0)
        if tag != 0x30:
            return None
        parts = _children(msg)
        if len(parts) != 3:
            return None
        version = int.from_bytes(parts[0][1], "big")
        community = parts[1][1].decode("latin-1", errors="replace")
        pdu_tag, pdu = parts[2]
        if pdu_tag != 0xA2:                       # GetResponse
            return None
        pdu_parts = _children(pdu)
        varbinds = _children(pdu_parts[3][1])
        if not varbinds:
            return {"version": version, "community": community, "sysdescr": None}
        pair = _children(varbinds[0][1])
        value_tag, value = pair[1]
        sysdescr = value.decode("utf-8", errors="replace") if value_tag == 0x04 else None
        return {"version": version, "community": community, "sysdescr": sysdescr}
    except (IndexError, ValueError):
        return None


# --------------------------------------------------------------- probing
def probe_snmp(ip, community=None, timeout=None, port=SNMP_PORT):
    """Send one SNMP GetRequest to ip:port. Returns None if nothing answered,
    otherwise a dict describing the reply (sysdescr may be None)."""
    request = build_snmp_get_request(community or SNMP_COMMUNITY)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout if timeout is not None else UDP_TIMEOUT)
        sock.sendto(request, (ip, port))
        data, _addr = sock.recvfrom(4096)
    except OSError:
        # Timeout, or an ICMP port-unreachable reported as a reset on Windows.
        return None
    finally:
        sock.close()
    parsed = parse_snmp_response(data)
    if parsed is None:
        parsed = {"version": None, "community": None, "sysdescr": None}
    parsed["responding"] = True
    return parsed


# --------------------------------------------------------------- DNS (port 53)
DNS_PORT = 53
NTP_PORT = 123


def build_dns_version_query(txid=0x4E53):
    """DNS query for version.bind (CHAOS class, TXT). Many servers answer it
    with their software version; a reply of any kind shows a DNS service."""
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in "version.bind".split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 16, 3)   # TXT, CH


def _skip_name(data, pos):
    while True:
        length = data[pos]
        if length & 0xC0 == 0xC0:          # compression pointer, two bytes
            return pos + 2
        if length == 0:
            return pos + 1
        pos += 1 + length


def parse_dns_response(data, txid=0x4E53):
    """Return {"version": text or None} for a reply with the matching id, else None."""
    try:
        rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if rid != txid or not flags & 0x8000:
            return None
        pos = 12
        for _ in range(qd):
            pos = _skip_name(data, pos) + 4
        version = None
        for _ in range(an):
            pos = _skip_name(data, pos)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            if rtype == 16 and rdata and version is None:
                version = rdata[1:1 + rdata[0]].decode("utf-8", errors="replace")
            pos += rdlen
        return {"version": version}
    except (struct.error, IndexError, ValueError):
        return None


def _exchange(ip, port, request, parser):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(UDP_TIMEOUT)
        sock.sendto(request, (ip, port))
        data, _addr = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()
    return parser(data)


def probe_dns(ip, port=DNS_PORT):
    reply = _exchange(ip, port, build_dns_version_query(), parse_dns_response)
    if reply is None:
        return None
    reply["responding"] = True
    return reply


# --------------------------------------------------------------- NTP (port 123)
def build_ntp_request():
    """48-byte NTP client request: leap 0, version 3, mode 3 (client)."""
    return b"\x1b" + b"\x00" * 47


def parse_ntp_response(data):
    """Return {"stratum": n} for a server reply (mode 4), else None."""
    if len(data) < 48 or (data[0] & 0x07) != 4:
        return None
    return {"stratum": data[1]}


def probe_ntp(ip, port=NTP_PORT):
    reply = _exchange(ip, port, build_ntp_request(), parse_ntp_response)
    if reply is None:
        return None
    reply["responding"] = True
    return reply


# ------------------------------------------------------------- combined results
def _probe_result(name, ip):
    if name == "snmp":
        reply = probe_snmp(ip)
        if not reply:
            return None
        text = (reply.get("sysdescr") or "SNMP responding")[:120]
        return {"port": SNMP_PORT, "service": "snmp", "banner": text}
    if name == "dns":
        reply = probe_dns(ip)
        if not reply:
            return None
        text = (reply.get("version") or "DNS responding")[:120]
        return {"port": DNS_PORT, "service": "dns", "banner": text}
    if name == "ntp":
        reply = probe_ntp(ip)
        if not reply:
            return None
        text = f"NTP stratum {reply.get('stratum')}"
        return {"port": NTP_PORT, "service": "ntp", "banner": text}
    return None


def udp_port_results(ip):
    """Port-result dicts for UDP services found on ip, in the same shape the TCP
    scanner produces. Empty when UDP scanning is disabled or nothing answers."""
    if not UDP_SCAN_ENABLED:
        return []
    results = []
    for name in ENABLED_PROBES:
        found = _probe_result(name, ip)
        if found:
            results.append({
                "port": found["port"],
                "protocol": "udp",
                "state": "open",
                "service": found["service"],
                "version": found["banner"],
                "banner": found["banner"],
            })
    return results
