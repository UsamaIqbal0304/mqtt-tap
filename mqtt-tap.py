#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Usama Iqbal (Plantroom Labs)
"""Point this at an MQTT broker nobody documented and it says what is on it.

    mqtt-tap.py tap <host>                     topic tree: rates, type guesses, last values
    mqtt-tap.py tap <host> --watch             live "topic  payload" stream
    mqtt-tap.py tap <host> --watch --key temperature      pull one field out of JSON payloads
    mqtt-tap.py tap <host> --stale             which topics stopped updating
    mqtt-tap.py tap <host> --json | --csv      the same survey, machine readable

The job it does
---------------
An engineer is handed a broker in a building: a hostname, maybe a password, no
inventory. The questions are always the same three — is anything publishing, on
what topics, and does the data look alive or frozen. This subscribes, listens
for a fixed window, and answers those three from what actually arrived.

Read-only by construction
-------------------------
This tool never publishes. It sends exactly five packet types: CONNECT,
SUBSCRIBE, PUBACK (only when it received a QoS 1 message, as the protocol
requires), PINGREQ, DISCONNECT. There is no PUBLISH encoder in this file at
all, so it cannot write a topic, cannot clear or overwrite a retained message,
and cannot register a will. Every outbound byte goes through send(), which
refuses any packet type outside that list; `mqtt-tap.py --self-check` runs that
refusal and prints the result.

It connects with clean session 1 and a distinctive random client id
("mqtt-tap-<hex>"), so it cannot take over a running client's session or make
the broker drop one.

What it implements
------------------
MQTT 3.1.1 (protocol level 4) on a raw socket: CONNECT/CONNACK,
SUBSCRIBE/SUBACK, inbound PUBLISH at QoS 0 and 1 with PUBACK,
PINGREQ/PINGRESP keepalive, DISCONNECT. Remaining-length varints are encoded
and decoded to spec (1-4 bytes, 268435455 max) and the receive path is a byte
buffer, so a PUBLISH split across several TCP reads, or several PUBLISHes
arriving in one read, are both handled.

A 5.0 broker's CONNACK is accepted too: if the CONNACK carries more than two
bytes the third is read as an MQTT 5 reason code and the property block is
skipped. That is the only 5.0 handling here — no properties are sent or
reported, and a broker that requires 5.0 will refuse the connection with
"unsupported protocol version", which this prints in words.

What it does not do
-------------------
No QoS 2 (it never subscribes above QoS 1). No session resumption. No Sparkplug
B payload decode: spBv1.0 topics are recognised by name and their payloads are
reported as binary with a byte count, never parsed. No MQTT 5 properties.

Exit codes
----------
    0   ran to the end of the window (even if nothing arrived — see the note
        printed in that case)
    2   usage error
    3   could not get a TCP/TLS connection (refused, unreachable, timed out,
        certificate not verified)
    4   broker answered CONNACK with a non-zero return code
    5   broker refused every topic filter (SUBACK 0x80)
    6   connection died mid-run: broker closed it, or keepalive timed out

Licence
-------
MIT. Copyright (c) 2026 Usama Iqbal (Plantroom Labs). Use it, change it, ship it
inside something you sell — the only condition is that the copyright line and
the permission notice travel with it. Full text:
https://plantroomlabs.com/tools/LICENSE.txt
"""

import argparse
import binascii
import csv
import fnmatch
import json
import os
import re
import select
import socket
import ssl
import sys
import time

# ---------------------------------------------------------------- wire format

CONNECT, CONNACK, PUBLISH, PUBACK = 1, 2, 3, 4
SUBSCRIBE, SUBACK = 8, 9
PINGREQ, PINGRESP, DISCONNECT = 12, 13, 14

PKT_NAME = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
            6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
            10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
            14: "DISCONNECT"}

# The whole outbound vocabulary of this tool. PUBLISH is deliberately absent.
ALLOWED_OUT = (CONNECT, SUBSCRIBE, PUBACK, PINGREQ, DISCONNECT)

MAX_REMAINING = 268435455

# MQTT 3.1.1 CONNACK return codes (3.2.2.3), in field words.
CONNACK_311 = {
    0: "connection accepted",
    1: "unacceptable protocol version - the broker will not talk MQTT 3.1.1 "
       "(level 4). It may be MQTT 5 only, or not an MQTT broker at all.",
    2: "identifier rejected - the broker refused our client id. Some brokers "
       "allow only a whitelist of ids; try --client-id <something they allow>.",
    3: "server unavailable - the broker answered but will not accept sessions "
       "right now (starting up, or a backend it needs is down).",
    4: "bad user name or password - credentials were sent and rejected. Check "
       "--user and the variable named by --pass-env.",
    5: "not authorised - the broker will not let this client connect at all "
       "(ACL or allow-list, not a password problem).",
}

# MQTT 5.0 CONNACK reason codes we may see if the broker answers in 5.0 style.
CONNACK_5 = {
    0x00: "success",
    0x80: "unspecified error",
    0x81: "malformed packet - the broker did not like our CONNECT",
    0x82: "protocol error",
    0x83: "implementation specific error",
    0x84: "unsupported protocol version - this broker requires MQTT 5.0; this "
          "tool speaks 3.1.1 only",
    0x85: "client identifier not valid",
    0x86: "bad user name or password",
    0x87: "not authorised",
    0x88: "server unavailable",
    0x89: "server busy",
    0x8A: "banned",
    0x8C: "bad authentication method",
    0x90: "topic name invalid",
    0x95: "packet too large",
    0x97: "quota exceeded",
    0x99: "payload format invalid",
    0x9A: "retain not supported",
    0x9B: "QoS not supported",
    0x9F: "connection rate exceeded",
}

SUBACK_OK = {0x00: "QoS 0", 0x01: "QoS 1", 0x02: "QoS 2"}

SPARKPLUG_PREFIX = "spBv1.0/"
SPARKPLUG_TYPES = ("NBIRTH", "NDEATH", "DBIRTH", "DDEATH", "NDATA", "DDATA",
                   "NCMD", "DCMD", "STATE")


class MqttError(Exception):
    """A protocol or network problem already phrased for a human."""

    def __init__(self, message, exit_code=3):
        Exception.__init__(self, message)
        self.exit_code = exit_code


def enc_remaining(n):
    """Remaining-length varint, MQTT 2.2.3."""
    if n < 0 or n > MAX_REMAINING:
        raise MqttError("cannot encode remaining length %d" % n, 2)
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n:
            byte |= 0x80
        out.append(byte)
        if not n:
            return bytes(out)


def dec_remaining(buf, start):
    """(value, index_after) from buf[start:], or (None, start) if incomplete.

    Raises MqttError on a 5th continuation byte, which is malformed per spec.
    """
    multiplier = 1
    value = 0
    i = start
    for _ in range(4):
        if i >= len(buf):
            return None, start
        byte = buf[i]
        i += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return value, i
        multiplier *= 128
    raise MqttError("malformed packet from broker: remaining length ran past "
                    "four bytes", 6)


def enc_string(text):
    """UTF-8 string with a 2-byte big-endian length, MQTT 1.5.3."""
    raw = text.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise MqttError("string too long for the wire: %d bytes" % len(raw), 2)
    return bytes([len(raw) >> 8, len(raw) & 0xFF]) + raw


def dec_string(body, i, what):
    if len(body) < i + 2:
        raise MqttError("truncated packet from broker: no length for %s" % what, 6)
    n = (body[i] << 8) | body[i + 1]
    i += 2
    if len(body) < i + n:
        raise MqttError("truncated packet from broker: %s claims %d bytes, "
                        "%d present" % (what, n, len(body) - i), 6)
    return body[i:i + n], i + n


def build_connect(client_id, keepalive, user=None, password=None):
    flags = 0x02                                   # clean session, no will
    payload = enc_string(client_id)
    if user is not None:
        flags |= 0x80
        payload += enc_string(user)
        if password is not None:
            flags |= 0x40
            raw = password.encode("utf-8")
            payload += bytes([len(raw) >> 8, len(raw) & 0xFF]) + raw
    variable = (enc_string("MQTT") + bytes([4, flags])
                + bytes([keepalive >> 8, keepalive & 0xFF]))
    return variable + payload


def build_subscribe(packet_id, filters, qos):
    body = bytes([packet_id >> 8, packet_id & 0xFF])
    for f in filters:
        body += enc_string(f) + bytes([qos])
    return body


def parse_publish(flags, body):
    """-> (topic, payload, qos, retain, dup, packet_id)"""
    qos = (flags >> 1) & 0x03
    if qos == 3:
        raise MqttError("malformed PUBLISH from broker: QoS 3 is not a thing", 6)
    retain = bool(flags & 0x01)
    dup = bool(flags & 0x08)
    raw_topic, i = dec_string(body, 0, "PUBLISH topic")
    packet_id = None
    if qos > 0:
        if len(body) < i + 2:
            raise MqttError("truncated PUBLISH from broker: QoS %d with no "
                            "packet id" % qos, 6)
        packet_id = (body[i] << 8) | body[i + 1]
        i += 2
    return (raw_topic.decode("utf-8", "replace"), body[i:], qos, retain, dup,
            packet_id)


# ------------------------------------------------------------------ transport

class Stream(object):
    """Byte buffer that yields whole MQTT packets as they complete.

    The point of this class is the case the naive version gets wrong: TCP hands
    back arbitrary slices, so one read can carry half a PUBLISH, or three
    PUBLISHes and a fragment. Packets are only yielded once the full remaining
    length is present.
    """

    def __init__(self):
        self.buf = bytearray()
        self.total_bytes = 0

    def feed(self, data):
        self.buf += data
        self.total_bytes += len(data)

    def packets(self):
        while True:
            if len(self.buf) < 2:
                return
            first = self.buf[0]
            length, after = dec_remaining(self.buf, 1)
            if length is None:
                return
            if len(self.buf) - after < length:
                return
            body = bytes(self.buf[after:after + length])
            del self.buf[:after + length]
            yield first, body


class Tap(object):
    """One read-only MQTT session."""

    def __init__(self, opts, log):
        self.o = opts
        self.log = log
        self.sock = None
        self.stream = Stream()
        self.packet_id = 0
        self.out_counts = {}
        self.last_send = 0.0
        self.last_recv = 0.0
        self.ping_sent_at = None
        self.pings = 0
        self.pongs = 0
        self.tls_peer = None
        self.phase = "connect"     # -> "listen" once the subscription is up

    # -- outbound ---------------------------------------------------------

    def send(self, packet_type, flags=0, body=b""):
        """The only place bytes leave this process.

        Refuses anything outside ALLOWED_OUT. That refusal is what makes the
        read-only claim checkable rather than a promise in a docstring.
        """
        if packet_type not in ALLOWED_OUT:
            raise MqttError(
                "refusing to send %s: mqtt-tap is read-only and sends only %s"
                % (PKT_NAME.get(packet_type, packet_type),
                   ", ".join(PKT_NAME[p] for p in ALLOWED_OUT)), 2)
        frame = (bytes([(packet_type << 4) | flags]) + enc_remaining(len(body))
                 + body)
        try:
            self.sock.sendall(frame)
        except socket.timeout:
            raise MqttError("timed out writing to %s - broker stopped reading"
                            % self.where(), 6)
        except ssl.SSLError as exc:
            raise MqttError(self.tls_alert(exc), 3 if self.phase == "connect" else 6)
        except OSError as exc:
            raise MqttError("lost the connection to %s while sending %s: %s"
                            % (self.where(), PKT_NAME.get(packet_type),
                               friendly_oserror(exc)), 6)
        self.out_counts[packet_type] = self.out_counts.get(packet_type, 0) + 1
        self.last_send = time.time()

    def next_packet_id(self):
        self.packet_id = (self.packet_id % 65535) + 1
        return self.packet_id

    def where(self):
        return "%s:%d" % (self.o.host, self.o.port)

    # -- connect ----------------------------------------------------------

    def open_socket(self):
        o = self.o
        try:
            infos = socket.getaddrinfo(o.host, o.port, 0, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise MqttError("cannot resolve host '%s': %s. Check the name, or "
                            "give an IP address." % (o.host, exc.strerror or exc), 3)
        last = None
        for family, stype, proto, _canon, addr in infos:
            try:
                sock = socket.socket(family, stype, proto)
                sock.settimeout(o.connect_timeout)
                sock.connect(addr)
                self.sock = sock
                break
            except OSError as exc:
                last = exc
                try:
                    sock.close()
                except Exception:
                    pass
        if self.sock is None:
            raise MqttError("cannot open TCP to %s: %s" % (self.where(),
                            friendly_oserror(last)), 3)
        if o.tls:
            self.wrap_tls()
        self.sock.settimeout(None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def wrap_tls(self):
        o = self.o
        try:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH,
                                             cafile=o.ca)
        except (OSError, ssl.SSLError) as exc:
            raise MqttError("cannot load CA file '%s': %s" % (o.ca, exc), 3)
        if o.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.log.warn("--insecure: the broker's certificate is NOT being "
                          "verified. The traffic is encrypted but you do not "
                          "know who you are talking to.")
        if o.cert:
            try:
                ctx.load_cert_chain(o.cert, o.cert_key)
            except (OSError, ssl.SSLError) as exc:
                raise MqttError("cannot load client certificate '%s'%s: %s"
                                % (o.cert,
                                   " with key '%s'" % o.cert_key if o.cert_key else "",
                                   exc), 3)
        try:
            self.sock = ctx.wrap_socket(self.sock, server_hostname=o.host)
        except ssl.SSLCertVerificationError as exc:
            raise MqttError(
                "TLS certificate verification failed for %s: %s.\n"
                "  The broker's certificate is not trusted by this machine. If "
                "it is signed by a private/site CA, pass --ca <ca.pem>. If the "
                "certificate names a different hostname than the one you dialled, "
                "connect using that name. --insecure skips the check entirely and "
                "leaves you encrypted but unauthenticated."
                % (self.where(), exc.verify_message or exc.reason or exc), 3)
        except ssl.SSLError as exc:
            raise MqttError(
                "TLS handshake failed with %s: %s.\n  A plain (non-TLS) broker "
                "on this port answers like this - try without --tls, or port "
                "1883." % (self.where(), exc.reason or exc), 3)
        except OSError as exc:
            raise MqttError("TLS handshake failed with %s: %s"
                            % (self.where(), friendly_oserror(exc)), 3)
        cipher = self.sock.cipher()
        cert = None
        try:
            cert = self.sock.getpeercert()
        except ValueError:
            cert = None
        self.tls_peer = {
            "protocol": self.sock.version(),
            "cipher": cipher[0] if cipher else None,
            "verified": not self.o.insecure,
            "subject": flatten_name(cert.get("subject")) if cert else None,
            "issuer": flatten_name(cert.get("issuer")) if cert else None,
            "not_after": cert.get("notAfter") if cert else None,
        }

    def tls_alert(self, exc):
        """Phrase a TLS alert that arrived after the handshake.

        TLS 1.3 lets the client finish the handshake before the server has
        judged it, so 'you needed a client certificate' and 'your certificate
        is not acceptable' both land on the first read or write rather than in
        wrap_socket. Reported as a connection problem they read like a network
        fault, which sends people to the wrong place.
        """
        text = str(exc)
        if "CERTIFICATE_REQUIRED" in text:
            return ("TLS: %s requires a client certificate (mutual TLS) and we "
                    "offered none. Pass --cert <client.pem> --cert-key "
                    "<client.key>. TLS 1.3 reports this just after the "
                    "handshake, which is why it looks like a dropped "
                    "connection." % self.where())
        if "UNKNOWN_CA" in text or "BAD_CERTIFICATE" in text or "DECRYPT_ERROR" in text:
            return ("TLS: %s rejected our client certificate (%s). The broker "
                    "does not trust the CA that signed --cert, or the cert and "
                    "--cert-key do not belong together."
                    % (self.where(), getattr(exc, "reason", None) or text))
        return ("TLS error talking to %s after the handshake: %s"
                % (self.where(), getattr(exc, "reason", None) or text))

    def read_once(self, timeout):
        """Wait up to timeout for bytes. Returns False if the broker closed."""
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return True
        try:
            data = self.sock.recv(65536)
        except ssl.SSLWantReadError:
            return True
        except socket.timeout:
            return True
        except ssl.SSLError as exc:
            raise MqttError(self.tls_alert(exc), 3 if self.phase == "connect" else 6)
        except OSError as exc:
            raise MqttError("connection to %s broke while reading: %s"
                            % (self.where(), friendly_oserror(exc)), 6)
        if not data:
            return False
        self.stream.feed(data)
        self.last_recv = time.time()
        return True

    def await_packet(self, want, deadline, what):
        """Read until a packet of type `want` arrives. Other packets are
        handled (a broker may send retained PUBLISHes the instant we SUBSCRIBE,
        and does not have to finish the SUBACK first)."""
        pending = []
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise MqttError(
                    "no %s from %s within %.0fs. The TCP connection opened, so "
                    "something is listening, but it is not answering MQTT "
                    "%s - wrong port, a TLS broker on a plain port, or a proxy."
                    % (what, self.where(), self.o.connect_timeout,
                       "3.1.1" if what == "CONNACK" else "promptly"), 3)
            alive = self.read_once(min(left, 0.5))
            if not alive:
                raise MqttError(
                    "%s closed the connection before sending %s. Brokers do "
                    "this when the CONNECT is rejected without a CONNACK "
                    "(some do that for a bad client id or a TLS-only listener)."
                    % (self.where(), what), 3 if what == "CONNACK" else 6)
            for first, body in self.stream.packets():
                if (first >> 4) == want:
                    return first, body, pending
                pending.append((first, body))

    def connect(self):
        self.open_socket()
        password = None
        if self.o.pass_env:
            if self.o.pass_env not in os.environ:
                raise MqttError("--pass-env %s: that environment variable is "
                                "not set, so there is no password to send."
                                % self.o.pass_env, 2)
            password = os.environ[self.o.pass_env]
        self.send(CONNECT, 0, build_connect(self.o.client_id, self.o.keepalive,
                                            self.o.user, password))
        deadline = time.time() + self.o.connect_timeout
        _first, body, pending = self.await_packet(CONNACK, deadline, "CONNACK")
        if len(body) < 2:
            raise MqttError("broker sent a %d-byte CONNACK; the spec requires "
                            "at least 2" % len(body), 6)
        session_present = bool(body[0] & 0x01)
        code = body[1]
        five = len(body) > 2          # MQTT 5 CONNACK carries a property block
        if code:
            table = CONNACK_5 if five else CONNACK_311
            text = table.get(code, "return code %d, which is not in the %s table"
                             % (code, "MQTT 5.0" if five else "MQTT 3.1.1"))
            raise MqttError("broker at %s refused the connection: %s (CONNACK "
                            "0x%02X%s)" % (self.where(), text, code,
                                           ", MQTT 5 style" if five else ""), 4)
        self.log.info("connected to %s%s as '%s' (CONNACK accepted%s%s)"
                      % (self.where(), " over TLS" if self.o.tls else "",
                         self.o.client_id,
                         ", MQTT 5 style" if five else "",
                         ", session present" if session_present else ""))
        if self.tls_peer:
            p = self.tls_peer
            self.log.info("  TLS %s, %s, certificate %s%s"
                          % (p["protocol"], p["cipher"],
                             "verified" if p["verified"] else "NOT verified",
                             "" if not p["subject"] else " (subject %s)" % p["subject"]))
        return pending

    def subscribe(self, filters):
        """-> (granted_filters, refused_filters). Raises if all are refused."""
        pid = self.next_packet_id()
        self.send(SUBSCRIBE, 0x02, build_subscribe(pid, filters, self.o.qos))
        deadline = time.time() + self.o.connect_timeout
        _first, body, pending = self.await_packet(SUBACK, deadline, "SUBACK")
        if len(body) < 3:
            raise MqttError("broker sent a %d-byte SUBACK; expected a packet "
                            "id plus one code per filter" % len(body), 6)
        got_pid = (body[0] << 8) | body[1]
        if got_pid != pid:
            self.log.warn("SUBACK packet id %d does not match our SUBSCRIBE %d "
                          "- reading it anyway" % (got_pid, pid))
        codes = list(body[2:])
        if len(codes) != len(filters):
            self.log.warn("SUBACK carries %d return codes for %d topic filters"
                          % (len(codes), len(filters)))
        granted, refused = [], []
        for i, f in enumerate(filters):
            code = codes[i] if i < len(codes) else 0x80
            if code == 0x80:
                refused.append(f)
                self.log.warn("SUBACK 0x80 for '%s' - the broker refused this "
                              "subscription. That is an ACL decision on the "
                              "filter (or an invalid filter), not a network "
                              "fault." % f)
            elif code in SUBACK_OK:
                granted.append(f)
                self.log.info("subscribed '%s' at %s%s"
                              % (f, SUBACK_OK[code],
                                 " (asked for QoS %d)" % self.o.qos
                                 if code < self.o.qos else ""))
            else:
                refused.append(f)
                self.log.warn("SUBACK 0x%02X for '%s' - not a code MQTT 3.1.1 "
                              "defines; treating it as a refusal" % (code, f))
        if not granted:
            raise MqttError(
                "the broker refused every topic filter (%s). The login "
                "succeeded, so this is a subscribe ACL: this account may "
                "connect but may not read those topics. Ask for the topics it "
                "is allowed, and pass them with --topic."
                % ", ".join("'%s'" % f for f in refused), 5)
        return granted, refused, pending

    def puback(self, packet_id):
        """Required by the protocol for a QoS 1 delivery. It acknowledges a
        message; it does not write anything to a topic."""
        self.send(PUBACK, 0, bytes([packet_id >> 8, packet_id & 0xFF]))

    # -- listen -----------------------------------------------------------

    def listen(self, duration, on_publish, pending=(), max_messages=None):
        """Pump the socket for `duration` seconds. Returns a status string."""
        self.phase = "listen"
        for first, body in pending:
            self.dispatch(first, body, on_publish)
        start = time.time()
        end = start + duration
        half = max(1.0, self.o.keepalive / 2.0)
        status = "completed"
        while True:
            now = time.time()
            if now >= end:
                break
            if max_messages is not None and on_publish.progress >= max_messages:
                status = "hit --max"
                break
            if self.ping_sent_at is None and now - max(self.last_send,
                                                       self.last_recv) >= half:
                self.send(PINGREQ)
                self.pings += 1
                self.ping_sent_at = now
            if (self.ping_sent_at is not None
                    and now - self.ping_sent_at > self.o.keepalive):
                raise MqttError(
                    "keepalive timeout: no PINGRESP from %s in %ds. The socket "
                    "is still open but the broker is not servicing it (wedged, "
                    "overloaded, or a stateful firewall dropped the flow)."
                    % (self.where(), self.o.keepalive), 6)
            alive = self.read_once(min(0.25, max(0.0, end - now)))
            if not alive:
                return "broker closed the connection %.0fs into the window" % (
                    time.time() - start)
            for first, body in self.stream.packets():
                self.dispatch(first, body, on_publish)
                if max_messages is not None and on_publish.progress >= max_messages:
                    status = "hit --max"
                    break
        return status

    def dispatch(self, first, body, on_publish):
        ptype = first >> 4
        if ptype == PUBLISH:
            topic, payload, qos, retain, dup, pid = parse_publish(first & 0x0F,
                                                                  body)
            if qos == 1 and pid is not None:
                self.puback(pid)
            elif qos == 2:
                # We never subscribe above QoS 1, so a QoS 2 delivery means the
                # broker ignored our granted QoS. Count it, do not ack it.
                self.log.warn_once("qos2", "broker delivered a QoS 2 message "
                                   "though we subscribed at QoS %d; counting it "
                                   "but not completing the handshake"
                                   % self.o.qos)
            on_publish(topic, payload, qos, retain, dup)
        elif ptype == PINGRESP:
            self.pongs += 1
            self.ping_sent_at = None
        elif ptype == PUBACK:
            self.log.warn_once("stray_puback", "broker sent a PUBACK; this tool "
                               "never publishes, so that is not for us")
        elif ptype in (SUBACK, CONNACK):
            self.log.warn_once("late_ack", "a late %s arrived mid-window; "
                               "ignoring it" % PKT_NAME[ptype])
        else:
            self.log.warn_once("pkt%d" % ptype, "ignoring a %s packet from the "
                               "broker" % PKT_NAME.get(ptype, "type %d" % ptype))

    def disconnect(self):
        if self.sock is None:
            return
        try:
            self.send(DISCONNECT)
        except MqttError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def friendly_oserror(exc):
    if exc is None:
        return "no route tried"
    if isinstance(exc, ConnectionRefusedError):
        return ("connection refused - nothing is listening on that port "
                "(MQTT is usually 1883 plain, 8883 TLS)")
    if isinstance(exc, socket.timeout):
        return ("timed out with no answer - the port is filtered, or the host "
                "is not reachable")
    if isinstance(exc, ConnectionResetError):
        return "connection reset by the other end"
    if isinstance(exc, OSError) and exc.errno is not None:
        return "%s (errno %d)" % (exc.strerror or str(exc), exc.errno)
    return str(exc)


def flatten_name(rdn):
    if not rdn:
        return None
    parts = []
    for group in rdn:
        for key, value in group:
            parts.append("%s=%s" % (key, value))
    return ", ".join(parts)


# ------------------------------------------------------------------- payloads

def classify(topic, payload):
    """Guess what a payload is. -> (kind, rendered_value, parsed_or_None)

    A guess, and labelled as one: MQTT payloads are opaque bytes and nothing on
    the wire says what they mean.
    """
    if len(payload) == 0:
        return "empty", "", None
    if topic.startswith(SPARKPLUG_PREFIX):
        return ("binary (Sparkplug B, not decoded)",
                hexdump(payload), None)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", hexdump(payload), None
    if any(ord(c) < 9 for c in text):
        return "binary", hexdump(payload), None
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            parsed = json.loads(stripped)
        except ValueError:
            return "string (JSON-ish, will not parse)", text, None
        kind = "JSON object" if isinstance(parsed, dict) else "JSON array"
        return kind, text, parsed
    low = stripped.lower()
    if low in ("true", "false"):
        return "boolean", text, low == "true"
    if re.match(r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$", stripped):
        try:
            value = float(stripped)
        except ValueError:
            return "string", text, None
        return "number", text, value
    return "string", text, None


def hexdump(payload, limit=16):
    head = binascii.hexlify(payload[:limit]).decode("ascii")
    spaced = " ".join(head[i:i + 2] for i in range(0, len(head), 2))
    return "%s%s (%d bytes)" % (spaced, " ..." if len(payload) > limit else "",
                               len(payload))


def truncate(text, limit):
    flat = re.sub(r"\s+", " ", text).strip()
    if len(flat) <= limit:
        return flat
    return flat[:limit - 1] + "…"


def filter_matches(pattern, topic):
    """MQTT wildcard match if the pattern uses + or #, else a glob, else a
    substring. Field tools get handed all three shapes."""
    if "#" in pattern or "+" in pattern:
        return topic_filter_match(pattern, topic)
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(topic, pattern)
    return pattern in topic


def topic_filter_match(pattern, topic):
    pat = pattern.split("/")
    top = topic.split("/")
    # MQTT 4.7.2: a leading wildcard does not match topics starting with '$',
    # which is how brokers keep $SYS out of a '#' subscription. Missing this
    # rule is why a tap can look empty on a busy broker.
    if top and top[0].startswith("$") and pat[0] in ("#", "+"):
        return False
    i = 0
    while i < len(pat):
        if pat[i] == "#":
            return i == len(pat) - 1 and (i < len(top) or i == len(top))
        if i >= len(top):
            return False
        if pat[i] != "+" and pat[i] != top[i]:
            return False
        i += 1
    return len(pat) == len(top)


def extract_key(parsed, path):
    """jsonpath-lite: dotted keys, numeric segments index arrays.
    -> (found, value)"""
    cur = parsed
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and re.match(r"^-?\d+$", seg):
            idx = int(seg)
            if -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return False, None
        else:
            return False, None
    return True, cur


def sparkplug_parts(topic):
    """spBv1.0/<group>/<msgtype>/<node>[/<device>] -> dict, or None."""
    if not topic.startswith(SPARKPLUG_PREFIX):
        return None
    bits = topic.split("/")
    if len(bits) < 4:
        return {"group": bits[1] if len(bits) > 1 else "", "msgtype": "",
                "node": "", "device": None}
    return {"group": bits[1], "msgtype": bits[2], "node": bits[3],
            "device": bits[4] if len(bits) > 4 else None}


# ------------------------------------------------------------------ collector

class TopicStat(object):
    def __init__(self, topic):
        self.topic = topic
        self.count = 0
        self.bytes = 0
        self.first = None
        self.last = None
        self.retained = 0
        self.dup = 0
        self.qos = {}
        self.kinds = {}
        self.last_kind = ""
        self.last_value = ""
        self.last_raw_len = 0

    def add(self, payload, qos, retain, dup, kind, rendered, now):
        self.count += 1
        self.bytes += len(payload)
        if self.first is None:
            self.first = now
        self.last = now
        if retain:
            self.retained += 1
        if dup:
            self.dup += 1
        self.qos[qos] = self.qos.get(qos, 0) + 1
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        self.last_kind = kind
        self.last_value = rendered
        self.last_raw_len = len(payload)

    def kind_label(self):
        if not self.kinds:
            return "?"
        best = max(self.kinds.items(), key=lambda kv: kv[1])[0]
        if len(self.kinds) > 1:
            return "%s (mixed: %s)" % (best, ", ".join(sorted(self.kinds)))
        return best

    def rate(self, window):
        return self.count / window if window > 0 else 0.0


class Survey(object):
    """Collects the tap report. Also the on_publish callback."""

    def __init__(self, started):
        self.topics = {}
        self.count = 0
        self.bytes = 0
        self.started = started
        self.ended = started

    @property
    def progress(self):
        """What --max counts here: every message, since all are summarised."""
        return self.count

    def __call__(self, topic, payload, qos, retain, dup):
        now = time.time()
        kind, rendered, _parsed = classify(topic, payload)
        stat = self.topics.get(topic)
        if stat is None:
            stat = self.topics[topic] = TopicStat(topic)
        stat.add(payload, qos, retain, dup, kind, rendered, now)
        self.count += 1
        self.bytes += len(payload)
        self.ended = now


class Watcher(object):
    """Streams lines as messages arrive."""

    def __init__(self, opts, out, log):
        self.o = opts
        self.out = out
        self.log = log
        self.count = 0
        self.shown = 0
        self.skipped_no_key = 0
        self.csv = csv.writer(out) if opts.csv else None
        if self.csv:
            self.csv.writerow(["time", "topic", "qos", "retain", "value"])

    @property
    def progress(self):
        """What --max counts here: lines printed, not messages seen. Counting
        messages would end the run eight arrivals in when a --filter or --key
        means only two of them were shown."""
        return self.shown

    def __call__(self, topic, payload, qos, retain, dup):
        self.count += 1
        if self.o.filter and not filter_matches(self.o.filter, topic):
            return
        kind, rendered, parsed = classify(topic, payload)
        if self.o.key:
            if parsed is None or not isinstance(parsed, (dict, list)):
                self.skipped_no_key += 1
                return
            found, value = extract_key(parsed, self.o.key)
            if not found:
                self.skipped_no_key += 1
                return
            rendered = value if isinstance(value, str) else json.dumps(value)
        self.shown += 1
        stamp = time.strftime("%H:%M:%S", time.localtime())
        flags = "%s%s" % ("R" if retain else "-", "D" if dup else "-")
        if self.csv:
            self.csv.writerow([stamp, topic, qos, int(retain), rendered])
        elif self.o.json:
            self.out.write(json.dumps({"time": stamp, "topic": topic,
                                       "qos": qos, "retain": retain,
                                       "type": kind, "value": rendered}) + "\n")
        else:
            self.out.write("%s  q%d %s  %-40s  %s\n"
                           % (stamp, qos, flags, topic,
                              truncate(str(rendered), self.o.width)))
        self.out.flush()


# -------------------------------------------------------------------- reports

def build_tree(topics):
    root = {}
    for topic in topics:
        node = root
        for seg in topic.split("/"):
            node = node.setdefault(seg, {})
    return root


def tree_lines(node, stats, prefix="", path=""):
    out = []
    for seg in sorted(node):
        here = "%s/%s" % (path, seg) if path else seg
        stat = stats.get(here)
        kids = node[seg]
        label = "%s%s" % (prefix, seg)
        if stat is not None:
            out.append((label, stat))
        else:
            out.append((label + "/", None))
        out += tree_lines(kids, stats, prefix + "  ", here)
    return out


def stale_rows(survey, window, stale_after, end):
    rows = []
    for topic, s in survey.topics.items():
        age = end - (s.last or end)
        retained_only = s.count == s.retained and s.count > 0
        sp = sparkplug_parts(topic)
        if sp and sp["msgtype"] in ("NBIRTH", "DBIRTH", "NDEATH", "DDEATH",
                                    "STATE"):
            # A birth or death certificate is published once per session on
            # purpose. Calling it stale because it has not repeated is a false
            # positive, and a field tool that cries wolf gets ignored.
            verdict = ("Sparkplug %s - an event topic, published once per "
                       "session by design; its age is not a staleness signal"
                       % sp["msgtype"])
            stale = False
        elif retained_only and s.count == 1:
            verdict = ("retained only - the broker replayed a stored value and "
                       "nothing updated it in %.0fs" % window)
            stale = True
        elif age >= stale_after:
            verdict = "stale - last message %.1fs ago" % age
            stale = True
        else:
            verdict = "live"
            stale = False
        rows.append({"topic": topic, "age": age, "messages": s.count,
                     "retained": s.retained, "stale": stale,
                     "verdict": verdict})
    return sorted(rows, key=lambda r: (-r["age"], r["topic"]))


def sparkplug_rows(survey):
    nodes = {}
    for topic, s in survey.topics.items():
        parts = sparkplug_parts(topic)
        if not parts:
            continue
        key = (parts["group"], parts["node"], parts["device"])
        entry = nodes.setdefault(key, {"types": {}, "messages": 0, "last": None})
        entry["types"][parts["msgtype"]] = (
            entry["types"].get(parts["msgtype"], 0) + s.count)
        entry["messages"] += s.count
        if s.last and (entry["last"] is None or s.last > entry["last"]):
            entry["last"] = s.last
    rows = []
    for (group, node, device), e in sorted(nodes.items()):
        types = e["types"]
        if "NDEATH" in types or "DDEATH" in types:
            verdict = "published a death certificate - treat as offline"
        elif any(t in types for t in ("NDATA", "DDATA")):
            verdict = "publishing data"
        elif any(t in types for t in ("NBIRTH", "DBIRTH")):
            verdict = ("birth certificate only - no NDATA/DDATA arrived in the "
                       "window")
        elif "STATE" in types:
            verdict = "host STATE topic only"
        else:
            verdict = "message types: %s" % ", ".join(sorted(types))
        rows.append({"group": group, "node": node, "device": device,
                     "messages": e["messages"],
                     "types": ", ".join("%s x%d" % (t, n)
                                        for t, n in sorted(types.items())),
                     "verdict": verdict})
    return rows


def print_report(survey, tap, opts, window, out, log):
    end = survey.ended if survey.count else time.time()
    stats = survey.topics
    stale_after = (opts.stale_after if opts.stale_after is not None
                   else window / 2.0)
    out.write("\n# MQTT tap: %s\n\n" % tap.where())
    out.write("Listened %.1fs on %s as '%s'%s. %d messages on %d topics, "
              "%s of payload.\n"
              % (window, ", ".join("'%s'" % f for f in opts._granted),
                 opts.client_id, " over TLS" if opts.tls else "",
                 survey.count, len(stats), human_bytes(survey.bytes)))
    out.write("Keepalive %ds: %d PINGREQ sent, %d PINGRESP back.%s\n"
              % (opts.keepalive, tap.pings, tap.pongs,
                 "  Read-only: %s." % ", ".join(
                     "%d %s" % (n, PKT_NAME[p])
                     for p, n in sorted(tap.out_counts.items()))))
    if opts._refused:
        out.write("Refused by the broker (SUBACK 0x80): %s\n"
                  % ", ".join("'%s'" % f for f in opts._refused))
    if not survey.count:
        out.write("\n" + no_traffic_note(tap, opts, window))
        return
    out.write("\n## topic tree\n\n")
    tree = build_tree(stats)
    for label, stat in tree_lines(tree, stats):
        if stat is None:
            out.write("%s\n" % label)
        else:
            out.write("%-44s %6d msg  %7.2f/s  %-32s %s%s\n"
                      % (label, stat.count, stat.rate(window),
                         truncate(stat.kind_label(), 32),
                         "[retained] " if stat.retained else "",
                         truncate(str(stat.last_value), 40)))
    out.write("\n## per topic\n\n")
    out.write("| Topic | Msgs | Msg/s | Type | Retain | Bytes | First | Last | "
              "Last value |\n")
    out.write("|---|---|---|---|---|---|---|---|---|\n")
    for topic in sorted(stats):
        s = stats[topic]
        out.write("| %s | %d | %.2f | %s | %s | %d | %s | %s | %s |\n"
                  % (topic, s.count, s.rate(window), s.kind_label(),
                     "yes (%d)" % s.retained if s.retained else "no",
                     s.bytes, clock(s.first), clock(s.last),
                     truncate(str(s.last_value), 48).replace("|", "\\|")))
    sp = sparkplug_rows(survey)
    if sp:
        out.write("\n## Sparkplug B (topic names only - payloads are not "
                  "decoded)\n\n")
        out.write("| Group | Node | Device | Msgs | Message types | Reading |\n")
        out.write("|---|---|---|---|---|---|\n")
        for r in sp:
            out.write("| %s | %s | %s | %d | %s | %s |\n"
                      % (r["group"], r["node"], r["device"] or "-",
                         r["messages"], r["types"], r["verdict"]))
    if opts.stale:
        rows = stale_rows(survey, window, stale_after, end)
        out.write("\n## staleness (no update for %.1fs counts as stale)\n\n"
                  % stale_after)
        out.write("| Topic | Last seen | Msgs | Retained | Reading |\n")
        out.write("|---|---|---|---|---|\n")
        for r in rows:
            out.write("| %s | %.1fs ago | %d | %d | %s |\n"
                      % (r["topic"], r["age"], r["messages"], r["retained"],
                         r["verdict"]))
        n_stale = sum(1 for r in rows if r["stale"])
        out.write("\n%d of %d topics look stale. A %.0fs window cannot tell a "
                  "dead sensor from a slow one - a value that updates every "
                  "five minutes is stale in every window shorter than that.\n"
                  % (n_stale, len(rows), window))
    out.write("\n_Payload types are guesses from the bytes; MQTT carries no "
              "type information. Rates are messages divided by the %.1fs "
              "window, not an instantaneous rate._\n" % window)


def no_traffic_note(tap, opts, window):
    alive = ("The session stayed up (%d PINGREQ, %d PINGRESP), so the broker "
             "was answering." % (tap.pings, tap.pongs)) if tap.pongs else (
             "No PINGRESP came back either, so the session may not have been "
             "healthy.")
    return (
        "Nothing arrived in %.1fs on %s.\n%s\nThree things look identical from "
        "here and this tool cannot tell them apart:\n"
        "  1. the broker is idle - nothing is publishing right now;\n"
        "  2. the subscription was accepted and then silently dropped - some "
        "brokers SUBACK a '#' filter and deliver nothing, because the ACL "
        "grants subscribe but not read;\n"
        "  3. the traffic is all retained and already-delivered, or lives "
        "under $SYS / another prefix that '#' does not cover ('#' does not "
        "match topics beginning with '$').\n"
        "Next: try --topic '$SYS/#', try a topic name you know, and run a "
        "longer --duration.\n" % (window, ", ".join("'%s'" % f for f in opts._granted), alive))


def clock(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-"


def human_bytes(n):
    for unit in ("B", "kB", "MB"):
        if n < 1024 or unit == "MB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def print_csv(survey, opts, window, out):
    w = csv.writer(out)
    w.writerow(["topic", "messages", "msgs_per_sec", "type", "retained_msgs",
                "bytes", "first_seen", "last_seen", "last_value"])
    for topic in sorted(survey.topics):
        s = survey.topics[topic]
        w.writerow([topic, s.count, "%.3f" % s.rate(window), s.kind_label(),
                    s.retained, s.bytes, clock(s.first), clock(s.last),
                    truncate(str(s.last_value), 120)])


def print_json(survey, tap, opts, window, out, warnings):
    end = survey.ended if survey.count else time.time()
    stale_after = (opts.stale_after if opts.stale_after is not None
                   else window / 2.0)
    doc = {
        "broker": {"host": opts.host, "port": opts.port, "tls": bool(opts.tls)},
        "tls": tap.tls_peer,
        "session": {"client_id": opts.client_id, "clean_session": True,
                    "keepalive": opts.keepalive, "qos_requested": opts.qos,
                    "pingreq": tap.pings, "pingresp": tap.pongs,
                    "packets_sent": dict((PKT_NAME[p], n) for p, n
                                         in tap.out_counts.items())},
        "subscriptions": {"granted": opts._granted, "refused": opts._refused},
        "window_seconds": round(window, 3),
        "messages": survey.count,
        "payload_bytes": survey.bytes,
        "topics": [],
        "warnings": warnings,
    }
    for topic in sorted(survey.topics):
        s = survey.topics[topic]
        row = {"topic": topic, "messages": s.count,
               "msgs_per_sec": round(s.rate(window), 4),
               "type": s.kind_label(), "types": s.kinds,
               "retained_msgs": s.retained, "dup_msgs": s.dup,
               "qos": dict((str(k), v) for k, v in s.qos.items()),
               "bytes": s.bytes, "first_seen": clock(s.first),
               "last_seen": clock(s.last),
               "last_value": truncate(str(s.last_value), 200),
               "last_payload_bytes": s.last_raw_len}
        sp = sparkplug_parts(topic)
        if sp:
            row["sparkplug"] = sp
            row["sparkplug_payload_decoded"] = False
        doc["topics"].append(row)
    if opts.stale:
        doc["stale_after_seconds"] = round(stale_after, 3)
        doc["staleness"] = [
            {"topic": r["topic"], "seconds_since_last": round(r["age"], 3),
             "messages": r["messages"], "retained_msgs": r["retained"],
             "stale": r["stale"], "reading": r["verdict"]}
            for r in stale_rows(survey, window, stale_after, end)]
    doc["sparkplug_nodes"] = sparkplug_rows(survey)
    out.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")


# ------------------------------------------------------------------------ log

class Log(object):
    def __init__(self, stream, quiet=False):
        self.stream = stream
        self.quiet = quiet
        self.seen = set()
        self.warnings = []

    def info(self, text):
        if not self.quiet:
            self.stream.write("mqtt-tap: %s\n" % text)
            self.stream.flush()

    def warn(self, text):
        self.warnings.append(text)
        self.stream.write("mqtt-tap: warning: %s\n" % text)
        self.stream.flush()

    def warn_once(self, key, text):
        if key in self.seen:
            return
        self.seen.add(key)
        self.warn(text)


# ------------------------------------------------------------------------ CLI

EPILOG = """\
notes
  Read-only. It sends CONNECT, SUBSCRIBE, PUBACK (for QoS 1 deliveries),
  PINGREQ and DISCONNECT, and nothing else. There is no PUBLISH code path, so
  it cannot write a topic, clear a retained message or leave a will behind.

  --key names a field inside JSON payloads (--key temperature, --key
  sensor.0.value). The TLS client private key is --cert-key, not --key.

  Default port is 1883, or 8883 with --tls.

examples
  mqtt-tap.py tap 10.4.2.9
  mqtt-tap.py tap broker.example --duration 60 --stale --json > survey.json
  mqtt-tap.py tap broker.example --watch --filter 'ahu/+/supplyTemp' --key value
  mqtt-tap.py tap broker.example --tls --ca site-ca.pem --user ro \\
      --pass-env MQTT_PASS --topic 'plant/#' --topic '$SYS/#'
"""


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="mqtt-tap.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__, epilog=EPILOG)
    ap.add_argument("--self-check", action="store_true",
                    help="run the codec and read-only checks and exit")
    sub = ap.add_subparsers(dest="command")
    t = sub.add_parser("tap", formatter_class=argparse.RawDescriptionHelpFormatter,
                       description="Subscribe, listen, report.", epilog=EPILOG,
                       help="survey a broker")
    t.add_argument("host")
    t.add_argument("--port", type=int, default=None,
                   help="default 1883, or 8883 with --tls")
    t.add_argument("--topic", action="append", default=None, metavar="FILTER",
                   help="topic filter to subscribe, repeatable (default '#')")
    t.add_argument("--duration", type=float, default=20.0, metavar="SEC",
                   help="how long to listen (default 20)")
    t.add_argument("--qos", type=int, choices=(0, 1), default=0,
                   help="QoS to request; QoS 2 is not implemented (default 0)")
    t.add_argument("--client-id", default=None,
                   help="default mqtt-tap-<random hex>, which cannot collide "
                        "with a client already on the broker")
    t.add_argument("--keepalive", type=int, default=30, metavar="SEC")
    t.add_argument("--connect-timeout", type=float, default=10.0, metavar="SEC")
    t.add_argument("--user", default=None)
    t.add_argument("--pass-env", default=None, metavar="VAR",
                   help="read the password from this environment variable, so "
                        "it never appears in ps output or shell history")
    t.add_argument("--tls", action="store_true")
    t.add_argument("--insecure", action="store_true",
                   help="with --tls: do not verify the broker certificate")
    t.add_argument("--ca", default=None, metavar="FILE",
                   help="CA bundle to verify the broker against")
    t.add_argument("--cert", default=None, metavar="FILE",
                   help="client certificate for mutual TLS")
    t.add_argument("--cert-key", "--tls-key", dest="cert_key", default=None,
                   metavar="FILE", help="private key for --cert")
    t.add_argument("--watch", action="store_true",
                   help="stream messages as they arrive instead of summarising")
    t.add_argument("--filter", default=None, metavar="PATTERN",
                   help="with --watch: keep topics matching this MQTT filter, "
                        "glob, or substring")
    t.add_argument("--key", default=None, metavar="PATH",
                   help="with --watch: print this field out of JSON payloads "
                        "(dotted path, numbers index arrays)")
    t.add_argument("--max", type=int, default=None, metavar="N",
                   help="stop after N lines printed (--watch) or N messages "
                        "collected (survey)")
    t.add_argument("--width", type=int, default=120, metavar="N",
                   help="truncate streamed payloads to N characters")
    t.add_argument("--stale", action="store_true",
                   help="add a staleness section, Sparkplug B aware by topic")
    t.add_argument("--stale-after", type=float, default=None, metavar="SEC",
                   help="no update for this long counts as stale "
                        "(default: half the window)")
    t.add_argument("--csv", action="store_true")
    t.add_argument("--json", action="store_true")
    t.add_argument("--quiet", action="store_true",
                   help="progress lines off (they go to stderr either way)")
    opts = ap.parse_args(argv)
    if opts.self_check:
        return opts
    if opts.command != "tap":
        ap.error("nothing to do: try 'mqtt-tap.py tap <host>' or --help")
    if opts.port is None:
        opts.port = 8883 if opts.tls else 1883
    if not opts.topic:
        opts.topic = ["#"]
    if opts.client_id is None:
        opts.client_id = "mqtt-tap-%s" % binascii.hexlify(os.urandom(4)).decode()
    if len(opts.client_id.encode("utf-8")) > 65535:
        ap.error("--client-id is too long for the wire")
    if opts.insecure and not opts.tls:
        ap.error("--insecure only means something with --tls")
    if opts.ca and not opts.tls:
        ap.error("--ca only means something with --tls")
    if opts.cert and not opts.tls:
        ap.error("--cert only means something with --tls")
    if opts.cert_key and not opts.cert:
        ap.error("--cert-key needs --cert")
    if opts.csv and opts.json:
        ap.error("choose one of --csv and --json")
    if opts.key and not opts.watch:
        ap.error("--key extracts fields from the --watch stream; add --watch")
    if opts.filter and not opts.watch:
        ap.error("--filter narrows the --watch stream; to narrow the survey "
                 "use --topic, which the broker applies")
    if opts.duration <= 0:
        ap.error("--duration must be positive")
    if opts.keepalive < 2:
        ap.error("--keepalive below 2s leaves no room for a PINGRESP")
    opts._granted, opts._refused = list(opts.topic), []
    return opts


def self_check():
    """Check the two things a reader should not have to take on trust: the
    varint codec, and that nothing can publish."""
    results = []

    def check(name, fn):
        try:
            fn()
            results.append((True, name, ""))
        except AssertionError as exc:
            results.append((False, name, str(exc)))
        except Exception as exc:                     # noqa: BLE001
            results.append((False, name, "%s: %s" % (type(exc).__name__, exc)))

    def varints():
        for n in (0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455):
            enc = enc_remaining(n)
            expect = {0: 1, 127: 1, 128: 2, 16383: 2, 16384: 3, 2097151: 3,
                      2097152: 4, 268435455: 4}.get(n)
            if expect:
                assert len(enc) == expect, "%d encoded to %d bytes" % (n, len(enc))
            got, idx = dec_remaining(bytearray(enc), 0)
            assert got == n and idx == len(enc), "%d round-tripped to %r" % (n, got)
        assert enc_remaining(127) == b"\x7f"
        assert enc_remaining(128) == b"\x80\x01"
        assert enc_remaining(268435455) == b"\xff\xff\xff\x7f"

    def varint_incomplete():
        got, idx = dec_remaining(bytearray(b"\x80"), 0)
        assert got is None and idx == 0, "incomplete varint should return None"
        try:
            dec_remaining(bytearray(b"\xff\xff\xff\xff\x7f"), 0)
        except MqttError:
            return
        raise AssertionError("a 5-byte remaining length should be rejected")

    def split_reads():
        # Three PUBLISHes, one with a 2-byte remaining length, fed one byte at
        # a time: the parser must yield exactly three whole packets.
        frames = b""
        for topic, payload in (("a/b", b"1"), ("c/d", b"x" * 300),
                               ("e/f", b"{}")):
            body = enc_string(topic) + payload
            frames += bytes([0x30]) + enc_remaining(len(body)) + body
        stream = Stream()
        seen = []
        for i in range(len(frames)):
            stream.feed(frames[i:i + 1])
            for first, body in stream.packets():
                seen.append(parse_publish(first & 0x0F, body))
        assert len(seen) == 3, "got %d packets from a byte-at-a-time feed" % len(seen)
        assert seen[1][0] == "c/d" and len(seen[1][1]) == 300, \
            "300-byte payload came back as %d bytes" % len(seen[1][1])
        stream.feed(frames)                      # all three in one read
        assert len(list(stream.packets())) == 3, "batched read lost a packet"

    def no_publish():
        assert PUBLISH not in ALLOWED_OUT, "PUBLISH is in the allowed list"
        tap = Tap(parse_args(["tap", "127.0.0.1"]), Log(sys.stderr, quiet=True))
        tap.sock = _NullSocket()
        for pkt in (PUBLISH, 5, 6, 7, 10):
            try:
                tap.send(pkt, 0, b"x")
            except MqttError:
                continue
            raise AssertionError("send() allowed %s" % PKT_NAME.get(pkt, pkt))
        tap.send(PINGREQ)
        assert tap.out_counts == {PINGREQ: 1}, "PINGREQ did not go out"
        # Assembled at runtime so this check does not match its own source.
        needle = b"def build_" + b"publish"
        src = open(os.path.abspath(__file__), "rb").read()
        assert needle not in src.replace(b'b"def build_" + b"publish"', b""), \
            "there is a PUBLISH builder in this file"

    def filters():
        cases = [("#", "a/b/c", True), ("a/#", "a", True), ("a/#", "a/b", True),
                 ("a/+", "a/b", True), ("a/+", "a/b/c", False),
                 ("a/+/c", "a/b/c", True), ("a/b", "a/b/c", False),
                 ("#", "$SYS/broker", False), ("+/x", "$SYS/x", False),
                 ("$SYS/#", "$SYS/broker/uptime", True)]
        for pattern, topic, want in cases:
            got = topic_filter_match(pattern, topic)
            assert got == want, "'%s' vs '%s' gave %s" % (pattern, topic, got)

    def payloads():
        cases = [("a", b'{"t":1}', "JSON object"), ("a", b"[1,2]", "JSON array"),
                 ("a", b"21.5", "number"), ("a", b"-3", "number"),
                 ("a", b"true", "boolean"), ("a", b"hello", "string"),
                 ("a", b"\x00\x01\x02\xff", "binary"), ("a", b"", "empty"),
                 ("spBv1.0/g/NDATA/n", b"\x08\x01", "binary (Sparkplug B, not decoded)")]
        for topic, payload, want in cases:
            kind = classify(topic, payload)[0]
            assert kind == want, "%r classified as %s, expected %s" % (
                payload, kind, want)
        found, value = extract_key(json.loads('{"a":{"b":[7,8]}}'), "a.b.1")
        assert found and value == 8, "dotted path gave %r" % (value,)
        assert extract_key({"a": 1}, "b")[0] is False, "missing key reported found"

    check("remaining-length varint round trip (0 .. 268435455)", varints)
    check("incomplete and over-long varints", varint_incomplete)
    check("PUBLISH split across TCP reads, and batched", split_reads)
    check("send() refuses every packet type except the read-only five", no_publish)
    check("topic filter wildcards, including $ topics", filters)
    check("payload type guesses and --key extraction", payloads)
    width = max(len(name) for _ok, name, _why in results)
    for ok, name, why in results:
        print("%-*s  %s%s" % (width, name, "PASS" if ok else "FAIL",
                              "  " + why if why else ""))
    bad = sum(1 for ok, _n, _w in results if not ok)
    print("\n%d checks, %d failed" % (len(results), bad))
    return 1 if bad else 0


class _NullSocket(object):
    """Stands in for a socket in --self-check; drops whatever is written."""

    def sendall(self, data):
        return None

    def close(self):
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    opts = parse_args(argv)
    if opts.self_check:
        return self_check()
    log = Log(sys.stderr, quiet=opts.quiet)
    out = sys.stdout
    tap = Tap(opts, log)
    try:
        pending = tap.connect()
        granted, refused, more = tap.subscribe(opts.topic)
    except MqttError as exc:
        sys.stderr.write("mqtt-tap: %s\n" % exc)
        tap.disconnect()
        return exc.exit_code
    opts._granted, opts._refused = granted, refused
    sink = Watcher(opts, out, log) if opts.watch else Survey(time.time())
    started = time.time()
    failure = None
    status = "completed"
    try:
        status = tap.listen(opts.duration, sink, list(pending) + list(more),
                            opts.max)
    except MqttError as exc:
        failure = exc
        status = "aborted: %s" % exc
    except KeyboardInterrupt:
        status = "interrupted at the keyboard"
    window = max(0.001, time.time() - started)
    tap.disconnect()
    if opts.watch:
        log.info("%s after %.1fs: %d messages seen, %d printed%s"
                 % (status, window, sink.count, sink.shown,
                    ", %d skipped (no '%s' in the payload)"
                    % (sink.skipped_no_key, opts.key) if opts.key else ""))
    elif opts.json:
        print_json(sink, tap, opts, window, out, log.warnings)
    elif opts.csv:
        print_csv(sink, opts, window, out)
    else:
        print_report(sink, tap, opts, window, out, log)
        if status != "completed":
            out.write("\nRun ended early: %s\n" % status)
    if failure is not None:
        sys.stderr.write("mqtt-tap: %s\n" % failure)
        return failure.exit_code
    if status.startswith("broker closed"):
        sys.stderr.write("mqtt-tap: %s - the survey above covers only the part "
                         "of the window that ran.\n" % status)
        return 6
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nmqtt-tap: stopped\n")
        sys.exit(130)
    except BrokenPipeError:
        os._exit(0)
