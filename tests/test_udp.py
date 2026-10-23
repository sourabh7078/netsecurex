"""SNMP probe: encoding, parsing, and the probing logic (no network traffic)."""
import socket

import udp_probe as u


REFERENCE_GET_REQUEST = bytes.fromhex(
    "302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500"
)


def test_request_matches_reference_bytes():
    assert u.build_snmp_get_request("public") == REFERENCE_GET_REQUEST


def test_parse_round_trip_with_sysdescr():
    descr = b"Linux metasploitable 2.6.24"
    varbind = u._tlv(0x30, u.encode_oid(u.SYS_DESCR_OID) + u._tlv(0x04, descr))
    pdu = u._tlv(0xA2, u._integer(1) + u._integer(0) + u._integer(0) + u._tlv(0x30, varbind))
    msg = u._tlv(0x30, u._integer(0) + u._tlv(0x04, b"public") + pdu)
    parsed = u.parse_snmp_response(msg)
    assert parsed == {"version": 0, "community": "public", "sysdescr": "Linux metasploitable 2.6.24"}


def test_parse_rejects_garbage():
    assert u.parse_snmp_response(b"") is None
    assert u.parse_snmp_response(b"\x01\x02\x03") is None
    assert u.parse_snmp_response(REFERENCE_GET_REQUEST) is None   # a request, not a response


def test_long_length_form_encodes_correctly():
    assert u._length(200) == b"\x81\xc8"
    assert u._length(5) == b"\x05"


class _FakeSocket:
    reply = None          # bytes to return, or an exception instance to raise
    sent = []

    def __init__(self, *a, **k):
        self.closed = False

    def settimeout(self, _t):
        pass

    def sendto(self, data, addr):
        _FakeSocket.sent.append((data, addr))

    def recvfrom(self, _n):
        if isinstance(_FakeSocket.reply, Exception):
            raise _FakeSocket.reply
        return _FakeSocket.reply, ("10.0.0.5", 161)

    def close(self):
        self.closed = True


def test_probe_returns_reply_details(monkeypatch):
    descr = b"Linux box"
    varbind = u._tlv(0x30, u.encode_oid(u.SYS_DESCR_OID) + u._tlv(0x04, descr))
    pdu = u._tlv(0xA2, u._integer(1) + u._integer(0) + u._integer(0) + u._tlv(0x30, varbind))
    _FakeSocket.reply = u._tlv(0x30, u._integer(0) + u._tlv(0x04, b"public") + pdu)
    _FakeSocket.sent = []
    monkeypatch.setattr(u.socket, "socket", _FakeSocket)
    result = u.probe_snmp("10.0.0.5")
    assert result["responding"] is True
    assert result["sysdescr"] == "Linux box"
    assert _FakeSocket.sent[0][1] == ("10.0.0.5", 161)


def test_probe_returns_none_on_timeout(monkeypatch):
    _FakeSocket.reply = socket.timeout("no answer")
    monkeypatch.setattr(u.socket, "socket", _FakeSocket)
    assert u.probe_snmp("10.0.0.6") is None


def test_probe_returns_none_on_connection_reset(monkeypatch):
    # Windows reports ICMP port-unreachable as a reset on the next recvfrom.
    _FakeSocket.reply = ConnectionResetError("closed")
    monkeypatch.setattr(u.socket, "socket", _FakeSocket)
    assert u.probe_snmp("10.0.0.7") is None


def test_responding_but_unparsed_still_counts_as_open(monkeypatch):
    _FakeSocket.reply = b"\xff\xfe not snmp"
    monkeypatch.setattr(u.socket, "socket", _FakeSocket)
    result = u.probe_snmp("10.0.0.8")
    assert result is not None and result["responding"] is True and result["sysdescr"] is None


def test_udp_port_results_shape(monkeypatch):
    monkeypatch.setattr(u, "UDP_SCAN_ENABLED", True)
    monkeypatch.setattr(u, "ENABLED_PROBES", ["snmp"])
    monkeypatch.setattr(u, "probe_snmp", lambda ip, **k: {"responding": True, "sysdescr": "Linux x"})
    [port] = u.udp_port_results("10.0.0.9")
    assert port["port"] == 161 and port["protocol"] == "udp"
    assert port["service"] == "snmp" and port["state"] == "open"
    assert port["version"] == "Linux x"


def test_udp_disabled_sends_nothing(monkeypatch):
    monkeypatch.setattr(u, "UDP_SCAN_ENABLED", False)
    called = []
    monkeypatch.setattr(u, "probe_snmp", lambda ip, **k: called.append(ip))
    assert u.udp_port_results("10.0.0.9") == []
    assert called == []
