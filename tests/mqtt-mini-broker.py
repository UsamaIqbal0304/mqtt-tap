#!/usr/bin/env python3
"""A throwaway MQTT 3.1.1 broker that exists so mqtt-tap.py can be tested.

    mqtt-mini-broker.py [--port N] [--port-file FILE] [--script-seconds 12] ...

It binds 127.0.0.1 only. It is not a broker anyone should run for real: no
persistence, one client at a time, no QoS 2, no unsubscribe, no will.

What it is for
--------------
There is no MQTT broker on this machine and the test must not touch a public
one, so the test needs a peer that speaks the wire format. This fixture is
written from the MQTT 3.1.1 spec directly and shares no code with mqtt-tap.py
on purpose: if the tool and the fixture used one encoder, a passing test would
only prove the encoder agreed with itself. Two independent implementations
agreeing on the bytes is the actual evidence.

What it does, and which tool behaviour each part exercises
----------------------------------------------------------
    CONNECT/CONNACK           the handshake, and every refusal code on demand
    --connack5                a 3-byte MQTT 5 style CONNACK with a property
                              block, so the tool's 5.0 CONNACK path is real
    SUBSCRIBE/SUBACK          '#' and '+' matching, per-filter granted QoS
    --refuse-filter           SUBACK 0x80 on a filter (an ACL refusal)
    --drop-hash               SUBACK success for '#' then deliver nothing
    retained store            replayed on subscribe, including one topic that
                              is never updated afterwards (for --stale)
    scripted publishes        JSON, number, boolean, string, binary blob, a
                              20 kB payload (3-byte remaining length), and
                              spBv1.0 topics with protobuf-shaped bytes
    --chunk N                 write every packet in N-byte pieces so PUBLISHes
                              land split across the tool's TCP reads
    QoS 1 out                 expects a PUBACK back and counts them
    $SYS topics               published, and withheld from wildcard filters
                              per MQTT 4.7.2, so a '#' tap must not see them
    PINGREQ/PINGRESP          --no-pingresp makes the tool time out its keepalive

On the way out it prints one SESSION line per connection with what it saw,
including client_publishes= - which must be 0, because the tool under test
claims it never publishes. The fixture treats any inbound PUBLISH as a
violation and says so.
"""

import argparse
import json
import os
import random
import select
import socket
import ssl
import struct
import sys
import time

CONNECT, CONNACK, PUBLISH, PUBACK = 1, 2, 3, 4
PUBREC, PUBREL, PUBCOMP = 5, 6, 7
SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK = 8, 9, 10, 11
PINGREQ, PINGRESP, DISCONNECT = 12, 13, 14
NAMES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
         6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
         10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
         14: "DISCONNECT"}


# ------------------------------------------------------- wire, written locally

def put_varint(value):
    """MQTT remaining length. Written here from the spec's algorithm."""
    chunks = []
    while True:
        value, digit = divmod(value, 128)
        if value > 0:
            digit = digit | 0x80
        chunks.append(digit)
        if value == 0:
            return bytes(chunks)


def take_varint(data, offset):
    """-> (value, new_offset) or (None, offset) when more bytes are needed."""
    value = 0
    shift = 0
    pos = offset
    while True:
        if pos >= len(data):
            return None, offset
        if shift > 21:
            raise Wire("remaining length exceeds four bytes")
        digit = data[pos]
        pos += 1
        value |= (digit & 0x7F) << shift
        if not digit & 0x80:
            return value, pos
        shift += 7


def put_text(text):
    raw = text.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def take_text(data, offset):
    (length,) = struct.unpack_from("!H", data, offset)
    offset += 2
    if len(data) < offset + length:
        raise Wire("string runs past the end of the packet")
    return data[offset:offset + length].decode("utf-8", "replace"), offset + length


def frame(ptype, flags, body):
    return struct.pack("!B", (ptype << 4) | flags) + put_varint(len(body)) + body


class Wire(Exception):
    pass


def asks_for_refused(refuse_filter, requested):
    """Refuse a filter that is aimed at the protected area, not a broad one.

    This is how brokers actually behave: 'secure/#' is refused outright with
    SUBACK 0x80, while a plain '#' is granted and the ACL simply never delivers
    the protected topics. Refusing '#' as well would make the fixture easier to
    pass and less like the field.
    """
    guard = refuse_filter.split("/")[0]
    if guard in ("#", "+"):
        return True
    return requested.split("/")[0] == guard


def filter_match(pattern, topic):
    """MQTT 4.7 matching, independent of the tool's version."""
    p = pattern.split("/")
    t = topic.split("/")
    if t[0].startswith("$") and p[0] in ("#", "+"):
        return False              # 4.7.2: wildcards do not reach $ topics
    for idx, seg in enumerate(p):
        if seg == "#":
            return idx == len(p) - 1
        if idx >= len(t):
            return False
        if seg != "+" and seg != t[idx]:
            return False
    return len(p) == len(t)


# ------------------------------------------------------------- scripted world

def telemetry(unit, tick):
    return json.dumps({"unit": unit, "temperature": round(20 + (tick % 7) * 0.5, 2),
                       "setpoint": 21.0, "mode": "cool",
                       "seq": tick}).encode("utf-8")


def sparkplug_payload(seq, metric):
    """Protobuf-shaped bytes: field 1 varint timestamp, field 2 a length
    delimited submessage, field 3 varint seq. Not a real Sparkplug payload and
    the tool is not expected to decode it - only to call it binary."""
    body = b"\x08" + put_varint(1759000000 + seq)
    inner = b"\x0a" + bytes([len(metric)]) + metric + b"\x15" + struct.pack("<f", 20.0 + seq)
    body += b"\x12" + bytes([len(inner)]) + inner
    body += b"\x18" + put_varint(seq)
    return body


BLOB = bytes(range(256)) + bytes(range(44))          # 300 bytes, not valid UTF-8


def big_json():
    rows = [{"t": 1759000000 + i, "v": round(20 + (i % 13) * 0.25, 3)}
            for i in range(900)]
    return json.dumps(rows).encode("utf-8")          # ~20 kB -> 3-byte varint


# Retained before any client connects. The frozen one is never updated again,
# which is what --stale is supposed to notice.
RETAINED = [
    ("building/ahu1/setpointFrozen", b"21.5"),
    ("building/ahu1/commissionedBy", b"Plantroom Labs 2024-03-11"),
    ("building/meter1/profile", BLOB),
]

SECRET_TOPIC = "secure/keys/master"


def schedule(seconds, qos1):
    """-> list of (when_seconds, topic, payload, qos, retain)."""
    items = []
    tick = 0
    t = 0.0
    while t < seconds:
        items.append((t, "building/ahu1/telemetry", telemetry("ahu1", tick), 0, False))
        items.append((t, "building/ahu1/supplyTemp",
                      ("%.2f" % (13.8 + (tick % 5) * 0.1)).encode(), 0, False))
        items.append((t + 0.1, "spBv1.0/Plant1/NDATA/edge1",
                      sparkplug_payload(tick, b"Inputs/Flow"), 0, False))
        if tick % 2 == 0:
            items.append((t + 0.05, "building/ahu2/telemetry",
                          telemetry("ahu2", tick), 0, False))
            items.append((t + 0.15, "building/ahu1/status",
                          b"OK" if tick % 4 else b"in alarm", 0, False))
        if tick % 3 == 0:
            items.append((t + 0.12, "building/ahu1/fanRunning",
                          b"true" if tick % 6 else b"false", 0, False))
            items.append((t + 0.18, "$SYS/broker/uptime",
                          ("%d seconds" % (600 + tick)).encode(), 0, False))
        if tick % 4 == 0:
            items.append((t + 0.2, "building/meter1/pulse", BLOB[:120], 0, False))
            items.append((t + 0.22, "building/alarm/latest",
                          json.dumps({"point": "ahu1/supplyTemp",
                                      "state": "high", "seq": tick}).encode(),
                          1 if qos1 else 0, False))
        tick += 1
        t += 0.25
    items.append((0.02, "spBv1.0/Plant1/NBIRTH/edge1",
                  sparkplug_payload(0, b"bdSeq"), 0, False))
    items.append((0.3, "building/ahu1/trendlog", big_json(), 0, False))
    # A zero-length payload is how a retained value gets cleared in the field,
    # and a non-ASCII topic name is common wherever the commissioning engineer
    # spoke something other than English. Both are here so the tool's handling
    # of them is asserted rather than assumed.
    items.append((0.4, "building/ahu1/clearedPoint", b"", 0, False))
    items.append((0.45, "building/ah\u00fc1/temp\u00e9rature",
                  '{"temperature": 19.5, "unit": "ah\u00fc1"}'.encode("utf-8"),
                  0, False))
    items.append((min(1.0, seconds / 2.0), SECRET_TOPIC, b"never delivered", 0, False))
    return sorted(items, key=lambda i: i[0])


# ------------------------------------------------------------------- session

class Session(object):
    def __init__(self, sock, peer, opts, log):
        self.sock = sock
        self.peer = peer
        self.o = opts
        self.log = log
        self.buf = bytearray()
        self.subs = []                  # [(filter, granted_qos)]
        self.refused = []
        self.client_id = None
        self.clean = None
        self.keepalive = None
        self.user = None
        self.next_pid = 1
        self.pub_out = 0
        self.qos1_out = 0
        self.pubacks_in = 0
        self.pingreq_in = 0
        self.client_publishes = 0
        self.retained_sent = 0
        self.closed_reason = "client closed"

    # -- io ---------------------------------------------------------------

    def write(self, data):
        """Chunked on purpose: --chunk 1 puts every packet across many TCP
        segments, which is the case a naive client parser gets wrong."""
        size = self.o.chunk or len(data)
        pieces = 0
        for i in range(0, len(data), size):
            self.sock.sendall(data[i:i + size])
            pieces += 1
            # A real pause on the first few boundaries guarantees the client
            # sees a half packet; pausing on every boundary of a 20 kB payload
            # would stall the whole script for seconds, which is what happened
            # the first time this was run.
            if self.o.chunk and pieces <= 8 and i + size < len(data):
                time.sleep(0.002)

    def read_packets(self, timeout):
        """-> list of (ptype, flags, body); None if the client went away."""
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if ready:
            try:
                data = self.sock.recv(65536)
            except (ssl.SSLWantReadError, socket.timeout):
                data = b""
            except OSError:
                return None
            if not data:
                return None
            self.buf += data
        out = []
        while True:
            if len(self.buf) < 2:
                break
            first = self.buf[0]
            length, after = take_varint(self.buf, 1)
            if length is None or len(self.buf) - after < length:
                break
            body = bytes(self.buf[after:after + length])
            del self.buf[:after + length]
            out.append((first >> 4, first & 0x0F, body))
        return out

    # -- handshake --------------------------------------------------------

    def handshake(self, deadline):
        while time.time() < deadline:
            packets = self.read_packets(0.2)
            if packets is None:
                return False
            for ptype, _flags, body in packets:
                if ptype != CONNECT:
                    self.log("expected CONNECT first, got %s"
                             % NAMES.get(ptype, ptype))
                    return False
                return self.on_connect(body)
        self.log("client never sent CONNECT")
        return False

    def on_connect(self, body):
        try:
            name, i = take_text(body, 0)
            level = body[i]
            flags = body[i + 1]
            (self.keepalive,) = struct.unpack_from("!H", body, i + 2)
            i += 4
            self.client_id, i = take_text(body, i)
            if flags & 0x04:                       # will flag - not supported
                _wt, i = take_text(body, i)
                (wlen,) = struct.unpack_from("!H", body, i)
                i += 2 + wlen
                self.log("VIOLATION: client sent a will (%s)" % _wt)
            if flags & 0x80:
                self.user, i = take_text(body, i)
            password = None
            if flags & 0x40:
                password, i = take_text(body, i)
        except (struct.error, IndexError, Wire) as exc:
            self.log("unreadable CONNECT: %s" % exc)
            return False
        self.clean = bool(flags & 0x02)
        if self.o.close_before_connack:
            self.closed_reason = "closed before CONNACK on purpose"
            return False
        code = 0
        if name != "MQTT" or level != 4:
            code = 1 if not self.o.connack5 else 0x84
        elif self.o.reject_version:
            code = 1 if not self.o.connack5 else 0x84
        elif self.o.reject_id:
            code = 2 if not self.o.connack5 else 0x85
        elif self.o.unavailable:
            code = 3 if not self.o.connack5 else 0x88
        elif self.o.require_auth:
            want_user, _, want_pass = self.o.require_auth.partition(":")
            if self.user != want_user or password != want_pass:
                code = 4 if not self.o.connack5 else 0x86
        elif self.o.not_authorised:
            code = 5 if not self.o.connack5 else 0x87
        if self.o.connack5:
            self.write(frame(CONNACK, 0, bytes([0, code, 0])))   # 0 properties
        else:
            self.write(frame(CONNACK, 0, bytes([0, code])))
        if code:
            self.closed_reason = "refused with CONNACK 0x%02X" % code
            self.log("refused '%s': CONNACK 0x%02X" % (self.client_id, code))
            return False
        self.log("accepted '%s' clean=%d keepalive=%d user=%s"
                 % (self.client_id, int(self.clean), self.keepalive, self.user))
        return True

    def on_subscribe(self, body):
        (pid,) = struct.unpack_from("!H", body, 0)
        i = 2
        codes = []
        while i < len(body):
            topic, i = take_text(body, i)
            asked = body[i] & 0x03
            i += 1
            if self.o.refuse_filter and asks_for_refused(self.o.refuse_filter, topic):
                codes.append(0x80)
                self.refused.append(topic)
                self.log("SUBACK 0x80 for '%s'" % topic)
                continue
            granted = min(asked, self.o.max_qos)
            self.subs.append((topic, granted))
            codes.append(granted)
            self.log("granted '%s' at QoS %d (asked %d)" % (topic, granted, asked))
        self.write(frame(SUBACK, 0, struct.pack("!H", pid) + bytes(codes)))
        return pid

    def granted_qos(self, topic):
        best = None
        for pattern, qos in self.subs:
            if filter_match(pattern, topic):
                best = qos if best is None else max(best, qos)
        return best

    def deliver(self, topic, payload, qos, retain):
        granted = self.granted_qos(topic)
        if granted is None:
            return False
        if self.o.refuse_filter and filter_match(self.o.refuse_filter, topic):
            return False        # ACL withholds it even from a granted '#'

        if self.o.drop_hash and any(p == "#" for p, _q in self.subs):
            return False                      # accepted the filter, delivers nothing
        use_qos = min(qos, granted)
        flags = (use_qos << 1) | (0x01 if retain else 0x00)
        body = put_text(topic)
        if use_qos > 0:
            body += struct.pack("!H", self.next_pid)
            self.next_pid = self.next_pid % 65535 + 1
            self.qos1_out += 1
        body += payload
        try:
            self.write(frame(PUBLISH, flags, body))
        except OSError:
            return False
        self.pub_out += 1
        return True

    def replay_retained(self):
        for topic, payload in RETAINED:
            if self.deliver(topic, payload, 0, True):
                self.retained_sent += 1

    # -- run --------------------------------------------------------------

    def run(self):
        if not self.handshake(time.time() + self.o.handshake_timeout):
            return
        deadline = time.time() + self.o.script_seconds
        subscribed_at = None
        items = None
        started = None
        while time.time() < deadline:
            packets = self.read_packets(0.02)
            if packets is None:
                self.closed_reason = "client closed the connection"
                return
            for ptype, flags, body in packets:
                if ptype == SUBSCRIBE:
                    self.on_subscribe(body)
                    if subscribed_at is None:
                        subscribed_at = time.time()
                        self.replay_retained()
                        items = schedule(self.o.script_seconds, not self.o.no_qos1)
                        started = time.time()
                elif ptype == PUBACK:
                    self.pubacks_in += 1
                elif ptype == PINGREQ:
                    self.pingreq_in += 1
                    if not self.o.no_pingresp:
                        self.write(frame(PINGRESP, 0, b""))
                elif ptype == PUBLISH:
                    self.client_publishes += 1
                    topic = "?"
                    try:
                        topic, _ = take_text(body, 0)
                    except Exception:
                        pass
                    self.log("VIOLATION: client PUBLISHed to '%s'" % topic)
                elif ptype == DISCONNECT:
                    self.closed_reason = "client sent DISCONNECT"
                    return
                elif ptype == UNSUBSCRIBE:
                    (pid,) = struct.unpack_from("!H", body, 0)
                    self.write(frame(UNSUBACK, 0, struct.pack("!H", pid)))
                else:
                    self.log("ignoring %s from client" % NAMES.get(ptype, ptype))
            if items is not None:
                now = time.time() - started
                while items and items[0][0] <= now:
                    when, topic, payload, qos, retain = items.pop(0)
                    self.deliver(topic, payload, qos, retain)
            if (self.o.close_after is not None
                    and started is not None
                    and time.time() - started >= self.o.close_after):
                self.closed_reason = ("broker closed the connection after %.1fs "
                                      "on purpose" % self.o.close_after)
                return
        self.closed_reason = "script finished"

    def summary(self):
        return ("SESSION client_id=%s clean=%s keepalive=%s user=%s "
                "filters=%s refused=%s pub_out=%d qos1_out=%d pubacks_in=%d "
                "pingreq_in=%d retained_sent=%d client_publishes=%d end=%s"
                % (self.client_id, self.clean, self.keepalive, self.user,
                   "|".join(p for p, _q in self.subs) or "-",
                   "|".join(self.refused) or "-", self.pub_out, self.qos1_out,
                   self.pubacks_in, self.pingreq_in, self.retained_sent,
                   self.client_publishes, self.closed_reason))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Binds 127.0.0.1 only, on purpose.")
    ap.add_argument("--port", type=int, default=0, help="0 picks a free port")
    ap.add_argument("--port-file", default=None,
                    help="write the chosen port here once listening")
    ap.add_argument("--script-seconds", type=float, default=12.0)
    ap.add_argument("--handshake-timeout", type=float, default=10.0)
    ap.add_argument("--sessions", type=int, default=1,
                    help="serve this many connections, then exit (0 = forever)")
    ap.add_argument("--chunk", type=int, default=0,
                    help="write packets in N-byte pieces (1 is the cruel case)")
    ap.add_argument("--max-qos", type=int, default=1, choices=(0, 1))
    ap.add_argument("--no-qos1", action="store_true",
                    help="publish everything at QoS 0")
    ap.add_argument("--refuse-filter", default="secure/#",
                    help="SUBACK 0x80 for filters that would reach this")
    ap.add_argument("--drop-hash", action="store_true",
                    help="accept a '#' subscription and then deliver nothing")
    ap.add_argument("--no-pingresp", action="store_true")
    ap.add_argument("--close-after", type=float, default=None, metavar="SEC")
    ap.add_argument("--close-before-connack", action="store_true")
    ap.add_argument("--require-auth", default=None, metavar="USER:PASS")
    ap.add_argument("--reject-version", action="store_true")
    ap.add_argument("--reject-id", action="store_true")
    ap.add_argument("--unavailable", action="store_true")
    ap.add_argument("--not-authorised", action="store_true")
    ap.add_argument("--connack5", action="store_true",
                    help="answer with an MQTT 5 style CONNACK")
    ap.add_argument("--lifetime", type=float, default=90.0, metavar="SEC",
                    help="exit after this long no matter what, so a failed "
                         "test cannot leave this process behind")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cert", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("--client-ca", default=None, metavar="FILE",
                    help="with --tls: require a client certificate signed by "
                         "(or equal to) this one - exercises mutual TLS")
    opts = ap.parse_args()
    random.seed(7)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", opts.port))
    listener.listen(4)
    port = listener.getsockname()[1]
    ctx = None
    if opts.tls:
        if not (opts.cert and opts.key):
            sys.stderr.write("--tls needs --cert and --key\n")
            return 2
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(opts.cert, opts.key)
        if opts.client_ca:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=opts.client_ca)

    def log(text):
        sys.stdout.write("broker: %s\n" % text)
        sys.stdout.flush()

    log("listening on 127.0.0.1:%d%s" % (port, " with TLS" if opts.tls else ""))
    if opts.port_file:
        with open(opts.port_file, "w") as fh:
            fh.write("%d\n" % port)
    served = 0
    violations = 0
    give_up_at = time.time() + opts.lifetime
    listener.settimeout(0.5)
    try:
        while opts.sessions == 0 or served < opts.sessions:
            if time.time() > give_up_at:
                log("lifetime of %.0fs reached, exiting" % opts.lifetime)
                break
            try:
                sock, peer = listener.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            sock.settimeout(None)      # do not inherit the listener timeout
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if ctx is not None:
                try:
                    sock = ctx.wrap_socket(sock, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    log("TLS handshake with %s:%d failed: %s"
                        % (peer[0], peer[1], exc))
                    log("SESSION client_id=None tls_handshake_failed=1")
                    served += 1
                    continue
            session = Session(sock, peer, opts, log)
            try:
                session.run()
            except (Wire, struct.error) as exc:
                log("dropping client after a wire error: %s" % exc)
            except OSError as exc:
                log("client socket error: %s" % exc)
            finally:
                log(session.summary())
                violations += session.client_publishes
                try:
                    sock.close()
                except OSError:
                    pass
            served += 1
    finally:
        listener.close()
    log("served %d session(s), %d client publish violations" % (served, violations))
    return 1 if violations else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
