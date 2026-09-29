#!/usr/bin/env bash
# Prove mqtt-tap.py against a loopback fixture, and record what was proved.
#
#   tests/test-mqtt-tap.sh [workdir]
#
# Every scenario starts tests/mqtt-mini-broker.py on 127.0.0.1 on a kernel-chosen
# port, runs the tool against it, and asserts on the bytes that came back. No
# external or public broker is contacted - not test.mosquitto.org, not HiveMQ,
# nothing off this box. The fixture binds loopback only and has its own
# independent wire codec, so agreement between the two is evidence rather than a
# tautology.
#
# Process hygiene: this script kills only the broker PIDs it started, by PID.
# It never pattern-kills, because other people's work runs on this machine.
#
# Leaves every tap stdout/stderr and broker log in the work directory (printed
# at the end) so a report can quote them instead of scrollback. Exit is non-zero
# if any assertion failed. Takes about a minute.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$HERE/../mqtt-tap.py"
BROKER="$HERE/mqtt-mini-broker.py"
WORK="${1:-$(mktemp -d /tmp/mqtt-tap-test.XXXXXX)}"
mkdir -p "$WORK"
START=$(date +%s)

[ -f "$TOOL" ]   || { echo "no tool at $TOOL" >&2; exit 2; }
[ -f "$BROKER" ] || { echo "no fixture at $BROKER" >&2; exit 2; }

PASS=0
FAIL=0
SUMMARY="$WORK/results.txt"
: > "$SUMMARY"

ok()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1" | tee -a "$SUMMARY"; }
no()  { FAIL=$((FAIL+1)); printf 'FAIL  %s -- %s\n' "$1" "$2" | tee -a "$SUMMARY"; }

eqn() { # got want name
  if [ "$1" = "$2" ]; then ok "$3 (=$1)"; else no "$3" "got '$1', wanted '$2'"; fi
}
has() { # file regex name
  if grep -qE -- "$2" "$1" 2>/dev/null; then ok "$3"
  else no "$3" "/$2/ not in $(basename "$1")"; fi
}
hasnt() { # file regex name
  if grep -qE -- "$2" "$1" 2>/dev/null; then no "$3" "/$2/ appears in $(basename "$1")"
  else ok "$3"; fi
}
atleast() { # got min name
  if [ "$1" -ge "$2" ] 2>/dev/null; then ok "$3 ($1 >= $2)"
  else no "$3" "got $1, wanted at least $2"; fi
}

BPID=""
PORT=""
start_broker() { # scenario_name broker args...
  local name="$1"; shift
  BLOG="$WORK/$name.broker.log"
  local pf="$WORK/$name.port"
  rm -f "$pf"
  python3 "$BROKER" --port-file "$pf" "$@" > "$BLOG" 2>&1 &
  BPID=$!
  PORT="$(python3 -c "
import sys, time
for _ in range(150):
    try:
        v = open(sys.argv[1]).read().strip()
        if v:
            print(v); sys.exit(0)
    except OSError:
        pass
    time.sleep(0.1)
sys.exit('fixture never reported a port')
" "$pf")" || { no "$name" "fixture did not start; see $BLOG"; PORT=""; return 1; }
  return 0
}
stop_broker() {
  if [ -n "$BPID" ]; then
    kill "$BPID" 2>/dev/null
    wait "$BPID" 2>/dev/null
    BPID=""
  fi
}
trap 'stop_broker' EXIT

tap() { # scenario_name tool args...  -> rc in $RC, files $OUT/$ERR
  local name="$1"; shift
  OUT="$WORK/$name.out"
  ERR="$WORK/$name.err"
  timeout 40 python3 "$TOOL" "$@" > "$OUT" 2> "$ERR"
  RC=$?
}

echo "work dir: $WORK"
echo "tool:     $TOOL"
echo

# ---------------------------------------------------------------- 1 self-check
echo "-- 1 codec and read-only self-check (no sockets)"
timeout 30 python3 "$TOOL" --self-check > "$WORK/selfcheck.out" 2>&1
eqn "$?" "0" "self-check exits 0"
has "$WORK/selfcheck.out" "^6 checks, 0 failed" "self-check: all 6 checks pass"
has "$WORK/selfcheck.out" "varint round trip.*PASS" "self-check: varint round trip"
has "$WORK/selfcheck.out" "split across TCP reads.*PASS" "self-check: split TCP reads"
has "$WORK/selfcheck.out" "send\(\) refuses.*PASS" "self-check: send() refuses PUBLISH"

echo
echo "-- 1b the two independent varint codecs agree on every length"
python3 - "$TOOL" "$BROKER" > "$WORK/codec-cross.out" 2>&1 <<'PY'
import importlib.util, sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = load("tool", sys.argv[1])
fix = load("fix", sys.argv[2])
values = list(range(0, 5000)) + [127, 128, 16383, 16384, 2097151, 2097152,
                                 268435454, 268435455, 100000, 1000000]
for n in values:
    a = tool.enc_remaining(n)
    b = fix.put_varint(n)
    assert a == b, "length %d: tool %r, fixture %r" % (n, a, b)
    # and each decodes the other's bytes
    got, _ = tool.dec_remaining(bytearray(b), 0)
    assert got == n, "tool read the fixture's %d as %d" % (n, got)
    got2, _ = fix.take_varint(a, 0)
    assert got2 == n, "fixture read the tool's %d as %d" % (n, got2)
print("OK %d lengths encode identically and decode across both codecs"
      % len(values))
PY
eqn "$?" "0" "tool and fixture varint codecs agree byte-for-byte"
has "$WORK/codec-cross.out" "^OK [0-9]+ lengths" "cross-decode of both codecs"

echo
echo "-- 1c --help states the read-only promise and the exit codes"
timeout 20 python3 "$TOOL" tap --help > "$WORK/help.out" 2>&1
eqn "$?" "0" "tap --help exits 0"
has "$WORK/help.out" "[Rr]ead-only" "--help says read-only"
has "$WORK/help.out" "no PUBLISH code path" "--help says there is no publish path"
has "$WORK/help.out" "never appears in ps output" "--help explains --pass-env"
timeout 20 python3 "$TOOL" --help > "$WORK/help-top.out" 2>&1
has "$WORK/help-top.out" "Exit codes" "--help documents the exit codes"
has "$WORK/help-top.out" "QoS 2" "--help says what is not implemented"

# ------------------------------------------------------------------- 2 survey
echo
echo "-- 2 survey of a busy broker: topic tree, types, retained, Sparkplug"
if start_broker s2 --script-seconds 14 --lifetime 60; then
  tap s2 tap 127.0.0.1 --port "$PORT" --duration 4 --qos 1 --stale
  eqn "$RC" "0" "survey exits 0"
  has "$OUT" "^## topic tree" "survey prints a topic tree"
  has "$OUT" "^## per topic" "survey prints a per-topic table"
  has "$OUT" "building/ahu1/telemetry \| [0-9]+ \| [0-9.]+ \| JSON object" "JSON object payload identified, with a rate"
  has "$OUT" "building/ahu1/supplyTemp .*number" "plain number payload identified"
  has "$OUT" "building/ahu1/fanRunning .*boolean" "boolean payload identified"
  has "$OUT" "building/ahu1/status .*string" "string payload identified"
  has "$OUT" "building/meter1/profile .*binary" "binary payload identified"
  has "$OUT" "building/meter1/profile.*\| 300 \|" "binary byte length reported"
  has "$OUT" "\[retained\]" "retain flag surfaced in the tree"
  has "$OUT" "clearedPoint \| 1 \| [0-9.]+ \| empty" "zero-length payload called empty, not a crash"
  if grep -qF 'building/ahü1/température' "$OUT"; then
    ok "non-ASCII topic name survived the round trip"
  else no "non-ASCII topic name survived the round trip" "not in $(basename "$OUT")"; fi
  has "$OUT" "setpointFrozen \| 1 \| [0-9.]+ \| number \| yes" "retained topic marked retained in the table"
  has "$OUT" "binary \(Sparkplug B, not decoded\)" "spBv1.0 payload called binary, not decoded"
  has "$OUT" "## Sparkplug B \(topic names only" "Sparkplug section is honest about topic-name-only"
  has "$OUT" "Plant1 \| edge1 .*publishing data" "Sparkplug node read as publishing"
  hasnt "$OUT" '\$SYS' "wildcard subscription did not receive \$SYS topics (MQTT 4.7.2)"
  hasnt "$OUT" "secure/keys/master" "ACL-withheld topic never appeared"
  MSGS=$(grep -oE '^Listened .* ([0-9]+) messages' "$OUT" | grep -oE '[0-9]+ messages' | grep -oE '^[0-9]+')
  atleast "${MSGS:-0}" "40" "survey collected messages"
  has "$OUT" "Read-only: 1 CONNECT" "tool reports its own outbound packet counts"
  hasnt "$OUT" "PUBLISH" "tool's own packet accounting lists no PUBLISH"
  stop_broker
  has "$BLOG" "client_publishes=0" "fixture saw zero client publishes"
  hasnt "$BLOG" "VIOLATION" "fixture logged no protocol violation"
  Q1=$(grep -oE 'qos1_out=[0-9]+' "$BLOG" | tail -1 | cut -d= -f2)
  PA=$(grep -oE 'pubacks_in=[0-9]+' "$BLOG" | tail -1 | cut -d= -f2)
  atleast "${Q1:-0}" "1" "fixture delivered QoS 1 messages"
  eqn "${PA:-x}" "${Q1:-y}" "one PUBACK back per QoS 1 delivery"
  RT=$(grep -oE 'retained_sent=[0-9]+' "$BLOG" | tail -1 | cut -d= -f2)
  atleast "${RT:-0}" "3" "fixture replayed retained messages"
  has "$BLOG" "clean=True" "tool connected with clean session"
  has "$BLOG" "client_id=mqtt-tap-" "tool used a distinctive client id"
fi

# ------------------------------------- 3 split reads and a 3-byte varint length
echo
echo "-- 3 byte-at-a-time writes, 27 kB payload (multi-byte remaining length)"
if start_broker s3 --script-seconds 12 --chunk 1 --lifetime 60; then
  tap s3 tap 127.0.0.1 --port "$PORT" --duration 4 --qos 1 --json
  eqn "$RC" "0" "survey over byte-at-a-time writes exits 0"
  stop_broker
  python3 - "$OUT" "$BROKER" > "$WORK/s3.check" 2>&1 <<'PY'
import importlib.util, json, sys
report, fixture = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("fix", fixture)
fix = importlib.util.module_from_spec(spec); spec.loader.exec_module(fix)
want = len(fix.big_json())
doc = json.load(open(report))
by = dict((t["topic"], t) for t in doc["topics"])
big = by.get("building/ahu1/trendlog")
assert big is not None, "the 20 kB topic never arrived intact"
assert big["last_payload_bytes"] == want, "got %d bytes, fixture sent %d" % (
    big["last_payload_bytes"], want)
assert big["type"] == "JSON array", "big payload typed as %s" % big["type"]
assert doc["messages"] >= 30, "only %d messages" % doc["messages"]
blob = by.get("building/meter1/profile")
assert blob and blob["last_payload_bytes"] == 300, "300-byte blob mangled"
print("OK payload of %d bytes reassembled from 1-byte TCP writes, %d messages"
      % (want, doc["messages"]))
PY
  eqn "$?" "0" "27 kB payload reassembled byte-for-byte from 1-byte writes"
  has "$WORK/s3.check" "^OK payload of" "byte count matches what the fixture sent"
fi

# --------------------------------------------- 4 watch mode, filter, key, max
echo
echo "-- 4 --watch with --filter, --key and --max"
if start_broker s4 --script-seconds 14 --lifetime 60; then
  tap s4 tap 127.0.0.1 --port "$PORT" --duration 20 --watch \
      --filter 'building/+/telemetry' --key temperature --max 8
  eqn "$RC" "0" "watch mode exits 0 after --max"
  stop_broker
  LINES=$(grep -c . "$OUT")
  eqn "$LINES" "8" "--max 8 printed exactly 8 lines"
  BAD=$(grep -cvE 'building/(ahu1|ahu2)/telemetry' "$OUT")
  eqn "$BAD" "0" "--filter kept only matching topics"
  NUM=$(grep -cE 'building/(ahu1|ahu2)/telemetry[[:space:]]+[0-9]+(\.[0-9]+)?$' "$OUT")
  eqn "$NUM" "8" "--key temperature extracted a bare number from each JSON payload"
  has "$ERR" "hit --max" "watch reports why it stopped"
fi

# ------------------------------------------------------------------- 5 --stale
echo
echo "-- 5 --stale separates a frozen retained topic from live ones"
if start_broker s5 --script-seconds 12 --lifetime 60; then
  tap s5 tap 127.0.0.1 --port "$PORT" --duration 4 --stale --json
  eqn "$RC" "0" "--stale exits 0"
  stop_broker
  python3 - "$OUT" > "$WORK/s5.check" 2>&1 <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
rows = dict((r["topic"], r) for r in doc["staleness"])
frozen = rows["building/ahu1/setpointFrozen"]
assert frozen["stale"] is True, "frozen retained topic not flagged"
assert frozen["retained_msgs"] == 1, "retained count wrong: %r" % frozen
assert "retained only" in frozen["reading"], frozen["reading"]
live = rows["building/ahu1/telemetry"]
assert live["stale"] is False, "a topic publishing 4/s was called stale"
birth = rows["spBv1.0/Plant1/NBIRTH/edge1"]
assert birth["stale"] is False, "a Sparkplug birth certificate called stale"
assert "event topic" in birth["reading"], birth["reading"]
sp = dict(((n["group"], n["node"]), n) for n in doc["sparkplug_nodes"])
assert ("Plant1", "edge1") in sp, "no Sparkplug node in the stale view"
assert doc["topics"], "no topics"
assert all(t.get("sparkplug_payload_decoded", False) is False
           for t in doc["topics"] if "sparkplug" in t), "claimed a decode"
print("OK frozen=%s live=%s sparkplug=%s"
      % (frozen["stale"], live["stale"], sp[("Plant1", "edge1")]["verdict"]))
PY
  eqn "$?" "0" "frozen retained topic flagged stale, live topic not"
  has "$WORK/s5.check" "^OK frozen=True live=False" "staleness verdicts as expected"
fi

# ------------------------------------------------- 6 subscription refused 0x80
echo
echo "-- 6 SUBACK 0x80: every filter refused"
if start_broker s6 --script-seconds 6 --lifetime 30; then
  tap s6 tap 127.0.0.1 --port "$PORT" --duration 3 --topic 'secure/#'
  eqn "$RC" "5" "all-filters-refused exits 5"
  has "$ERR" "SUBACK 0x80 for 'secure/#'" "0x80 named the filter"
  has "$ERR" "refused every topic filter" "refusal explained in words"
  has "$ERR" "subscribe ACL" "refusal attributed to an ACL, not the network"
  hasnt "$ERR" "Traceback" "no traceback on a refused subscription"
  stop_broker
  has "$BLOG" "SUBACK 0x80 for 'secure/#'" "fixture confirms it sent 0x80"
fi

# ------------------------------------------------- 7 partial refusal continues
echo
echo "-- 7 one filter refused, one granted: keep going"
if start_broker s7 --script-seconds 10 --lifetime 40; then
  tap s7 tap 127.0.0.1 --port "$PORT" --duration 3 --topic 'secure/#' --topic 'building/#'
  eqn "$RC" "0" "partial refusal still exits 0"
  has "$ERR" "SUBACK 0x80 for 'secure/#'" "refused filter reported"
  has "$OUT" "Refused by the broker \(SUBACK 0x80\): 'secure/#'" "report records the refusal"
  has "$OUT" "building/ahu1/telemetry" "granted filter still delivered data"
  stop_broker
fi

# --------------------------------------------------------- 8 CONNACK refusals
echo
echo "-- 8 CONNACK return codes, 3.1.1 and MQTT 5 style"
connack_case() { # name broker_flag expect_rc expect_text [tap args...]
  local name="$1" flag="$2" want_rc="$3" want_text="$4"; shift 4
  if start_broker "$name" $flag --script-seconds 4 --lifetime 25; then
    tap "$name" tap 127.0.0.1 --port "$PORT" --duration 2 "$@"
    eqn "$RC" "$want_rc" "$name exits $want_rc"
    has "$ERR" "$want_text" "$name says '$want_text'"
    hasnt "$ERR" "Traceback" "$name: no traceback"
    stop_broker
  fi
}
connack_case connack-version  "--reject-version"  4 "unacceptable protocol version"
connack_case connack-id       "--reject-id"       4 "identifier rejected"
connack_case connack-down     "--unavailable"     4 "server unavailable"
connack_case connack-authz    "--not-authorised"  4 "not authorised"
connack_case connack-creds    "--require-auth ro:s3cret" 4 "bad user name or password"
connack_case connack5-authz   "--connack5 --not-authorised" 4 "not authorised"
connack_case connack-closed   "--close-before-connack" 3 "closed the connection before sending CONNACK"

echo "   credentials that work, and an MQTT 5 style CONNACK that accepts"
if start_broker s8ok --require-auth ro:s3cret --script-seconds 8 --lifetime 30; then
  MQTT_TAP_PASS=s3cret tap s8ok tap 127.0.0.1 --port "$PORT" --duration 3 \
      --user ro --pass-env MQTT_TAP_PASS
  eqn "$RC" "0" "correct credentials connect"
  stop_broker
  has "$BLOG" "user=ro" "fixture saw the username"
  hasnt "$WORK/s8ok.err" "s3cret" "password never printed"
fi
if start_broker s8five --connack5 --script-seconds 8 --lifetime 30; then
  tap s8five tap 127.0.0.1 --port "$PORT" --duration 3
  eqn "$RC" "0" "MQTT 5 style CONNACK accepted"
  has "$ERR" "MQTT 5 style" "tool says it saw a 5.0 CONNACK"
  stop_broker
fi

# ------------------------------------------------- 9 refused TCP / usage error
echo
echo "-- 9 nothing listening, and a usage mistake"
DEADPORT=$(python3 -c "
import socket
s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); print(p)")
tap s9 tap 127.0.0.1 --port "$DEADPORT" --duration 2
eqn "$RC" "3" "connection refused exits 3"
has "$WORK/s9.err" "connection refused" "says 'connection refused' in words"
has "$WORK/s9.err" "nothing is listening" "explains what that means"
hasnt "$WORK/s9.err" "Traceback" "no traceback on a refused connection"
tap s9usage tap 127.0.0.1 --port 1883 --key temperature
eqn "$RC" "2" "--key without --watch is a usage error (exit 2)"

# --------------------------------------------- 10 keepalive, both outcomes
echo
echo "-- 10 keepalive: PINGREQ answered, and PINGRESP withheld"
if start_broker s10a --drop-hash --script-seconds 14 --lifetime 60; then
  tap s10a tap 127.0.0.1 --port "$PORT" --duration 6 --keepalive 2
  eqn "$RC" "0" "idle broker with working keepalive exits 0"
  has "$OUT" "Nothing arrived in" "silent subscription reported"
  has "$OUT" "silently dropped" "names the accepted-then-dropped case"
  has "$OUT" "the broker is idle" "offers the innocent explanation too"
  PINGS=$(grep -oE 'Keepalive [0-9]+s: [0-9]+ PINGREQ sent, [0-9]+ PINGRESP' "$OUT" | grep -oE '[0-9]+ PINGREQ' | grep -oE '^[0-9]+')
  PONGS=$(grep -oE '[0-9]+ PINGRESP' "$OUT" | grep -oE '^[0-9]+' | head -1)
  atleast "${PINGS:-0}" "1" "PINGREQ sent while idle"
  eqn "${PONGS:-x}" "${PINGS:-y}" "every PINGREQ answered"
  stop_broker
  has "$BLOG" "granted '#'" "fixture granted the '#' it then dropped"
fi
if start_broker s10b --drop-hash --no-pingresp --script-seconds 20 --lifetime 60; then
  tap s10b tap 127.0.0.1 --port "$PORT" --duration 15 --keepalive 2
  eqn "$RC" "6" "keepalive timeout exits 6"
  has "$ERR" "keepalive timeout" "says 'keepalive timeout'"
  has "$ERR" "not servicing it" "explains a half-open connection"
  hasnt "$ERR" "Traceback" "no traceback on a keepalive timeout"
  stop_broker
fi

# ------------------------------------------- 11 broker vanishes mid-window
echo
echo "-- 11 broker closes the connection mid-window"
if start_broker s11 --close-after 2 --script-seconds 20 --lifetime 60; then
  tap s11 tap 127.0.0.1 --port "$PORT" --duration 12
  eqn "$RC" "6" "mid-window close exits 6"
  has "$OUT" "broker closed the connection" "report says the broker closed it"
  has "$OUT" "^## per topic" "partial survey still printed"
  hasnt "$ERR" "Traceback" "no traceback when the broker vanishes"
  stop_broker
fi

# -------------------------------------------------------------------- 12 TLS
echo
echo "-- 12 TLS: verified, unverified, --insecure, and a client certificate"
CERTDIR="$WORK/tls"
mkdir -p "$CERTDIR"
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.pem" \
  -subj "/CN=localhost/O=mqtt-tap fixture" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" > "$WORK/openssl.log" 2>&1
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout "$CERTDIR/client.key" -out "$CERTDIR/client.pem" \
  -subj "/CN=mqtt-tap client" >> "$WORK/openssl.log" 2>&1
if [ -s "$CERTDIR/server.pem" ] && [ -s "$CERTDIR/client.pem" ]; then
  ok "throwaway self-signed certificates generated locally"
  if start_broker s12a --tls --cert "$CERTDIR/server.pem" --key "$CERTDIR/server.key" \
      --script-seconds 10 --lifetime 40; then
    tap s12a tap localhost --port "$PORT" --tls --ca "$CERTDIR/server.pem" --duration 2
    eqn "$RC" "0" "TLS with --ca connects"
    has "$ERR" "TLS TLSv1\.[23]" "reports the negotiated TLS version"
    has "$ERR" "certificate verified" "says the certificate was verified"
    has "$OUT" "building/ahu1/telemetry" "data flows over TLS"
    stop_broker
  fi
  if start_broker s12b --tls --cert "$CERTDIR/server.pem" --key "$CERTDIR/server.key" \
      --script-seconds 8 --lifetime 30; then
    tap s12b tap localhost --port "$PORT" --tls --duration 2
    eqn "$RC" "3" "untrusted certificate exits 3"
    has "$ERR" "certificate verification failed" "names the verification failure"
    has "$ERR" "\-\-ca" "suggests --ca for a private CA"
    has "$ERR" "insecure" "mentions --insecure and what it costs"
    hasnt "$ERR" "Traceback" "no traceback on a TLS verify failure"
    stop_broker
  fi
  if start_broker s12c --tls --cert "$CERTDIR/server.pem" --key "$CERTDIR/server.key" \
      --script-seconds 8 --lifetime 30; then
    tap s12c tap 127.0.0.1 --port "$PORT" --tls --insecure --duration 2
    eqn "$RC" "0" "--insecure connects to an untrusted certificate"
    has "$ERR" "NOT being verified" "warns loudly about --insecure"
    stop_broker
  fi
  if start_broker s12d --tls --cert "$CERTDIR/server.pem" --key "$CERTDIR/server.key" \
      --client-ca "$CERTDIR/client.pem" --script-seconds 10 --lifetime 40; then
    tap s12d tap localhost --port "$PORT" --tls --ca "$CERTDIR/server.pem" \
        --cert "$CERTDIR/client.pem" --cert-key "$CERTDIR/client.key" --duration 2
    eqn "$RC" "0" "mutual TLS with --cert/--cert-key connects"
    has "$OUT" "building/ahu1/telemetry" "data flows over mutual TLS"
    stop_broker
  fi
  if start_broker s12e --tls --cert "$CERTDIR/server.pem" --key "$CERTDIR/server.key" \
      --client-ca "$CERTDIR/client.pem" --script-seconds 8 --lifetime 30; then
    tap s12e tap localhost --port "$PORT" --tls --ca "$CERTDIR/server.pem" --duration 2
    eqn "$RC" "3" "missing client certificate exits 3"
    hasnt "$ERR" "Traceback" "no traceback when the broker demands a client cert"
    stop_broker
  fi
else
  no "TLS scenarios" "openssl did not produce certificates; see $WORK/openssl.log"
fi

# -------------------------------------------------------------------- 13 CSV
echo
echo "-- 13 --csv output is machine readable"
if start_broker s13 --script-seconds 10 --lifetime 40; then
  tap s13 tap 127.0.0.1 --port "$PORT" --duration 3 --csv
  eqn "$RC" "0" "--csv exits 0"
  stop_broker
  python3 - "$OUT" > "$WORK/s13.check" 2>&1 <<'PY'
import csv, sys
rows = list(csv.reader(open(sys.argv[1])))
assert rows, "empty csv"
head = rows[0]
assert head[0] == "topic" and "msgs_per_sec" in head, head
body = rows[1:]
assert len(body) >= 6, "only %d data rows" % len(body)
for r in body:
    assert len(r) == len(head), "ragged row: %r" % r
    float(r[head.index("msgs_per_sec")])
    int(r[head.index("messages")])
print("OK %d data rows, %d columns" % (len(body), len(head)))
PY
  eqn "$?" "0" "--csv parses as CSV with numeric columns"
fi

# --------------------------------------------------- 14 nothing ever published
echo
echo "-- 14 across every scenario: no publish, no traceback"
VIOL=$(grep -l "VIOLATION" "$WORK"/*.broker.log 2>/dev/null | wc -l)
eqn "$VIOL" "0" "no fixture logged a client PUBLISH or will"
NONZERO=$(grep -h -oE 'client_publishes=[0-9]+' "$WORK"/*.broker.log 2>/dev/null | grep -cv 'client_publishes=0')
eqn "$NONZERO" "0" "every SESSION line reports client_publishes=0"
SESSIONS=$(grep -h -o 'client_publishes=' "$WORK"/*.broker.log 2>/dev/null | wc -l)
atleast "${SESSIONS:-0}" "10" "sessions actually exercised"
TB=$(grep -l "Traceback" "$WORK"/*.err "$WORK"/*.out 2>/dev/null | wc -l)
eqn "$TB" "0" "no traceback in any tap stdout or stderr"

# ----------------------------------------------------------------- summary
ELAPSED=$(( $(date +%s) - START ))
echo
echo "================================================================"
printf '%d assertions: %d passed, %d failed, %ds elapsed\n' \
       "$((PASS+FAIL))" "$PASS" "$FAIL" "$ELAPSED"
echo "artifacts: $WORK"
echo "================================================================"
if [ "$FAIL" -gt 0 ]; then
  echo "failures:"
  grep '^FAIL' "$SUMMARY"
  exit 1
fi
exit 0
