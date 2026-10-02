# mqtt-tap

Point it at an MQTT broker and it tells you what is publishing, on what topics, and whether
the data is alive or frozen. It never publishes.

One Python file, standard library only.

```
mqtt-tap.py tap <host>                  topic tree: rates, type guesses, last values
mqtt-tap.py tap <host> --watch          live "topic  payload" stream
mqtt-tap.py tap <host> --watch --key temperature    pull one field out of JSON payloads
mqtt-tap.py tap <host> --stale          which topics stopped updating
mqtt-tap.py tap <host> --json | --csv   the same survey, machine readable
mqtt-tap.py --self-check                prove the codec and the write refusal
```

An engineer handed a broker in a building gets a hostname, maybe a password, and no
inventory. The three questions are always the same: is anything publishing, on what topics,
and does the data look alive or frozen. This subscribes, listens for a fixed window, and
answers those three from what actually arrived.

## Read this first: what it has actually been run against

**It has never been run against a real broker.** Not Mosquitto, not EMQX, not HiveMQ, not a
cloud IoT hub, and not Niagara's own MQTT driver — none of them, ever. Everything is proved
against `tests/mqtt-mini-broker.py`, a fixture broker in this repo that binds 127.0.0.1:

```
$ tests/test-mqtt-tap.sh
130 assertions: 130 passed, 0 failed, 48s elapsed
```

The fixture has its own independent encoder and decoder, written from the specification
rather than imported from the tool — which is what stops the suite from merely proving the
tool agrees with itself. But tool and fixture were written by the same person in the same
sitting, so a misreading of the specification could sit in both. Running it against a real
broker product is the one thing that would close that, and it has not been done.

## Install

No install. One file, standard library only — no pip, no `paho-mqtt`, no broker client
library, nothing to put on a machine you do not own. Written and run on Python 3.12.

```sh
curl -O https://raw.githubusercontent.com/UsamaIqbal0304/mqtt-tap/main/mqtt-tap.py
```

## Use

```sh
# watch a broker for the default twenty seconds and print what turned up
python3 mqtt-tap.py tap 10.0.4.12

# one branch only, for five minutes, with the staleness table
python3 mqtt-tap.py tap 10.0.4.12 --topic "site/plantroom/#" --duration 300 --stale

# the same survey as JSON or CSV, to keep
python3 mqtt-tap.py tap 10.0.4.12 --duration 300 --json > survey.json
```

`--port` is 1883 by default and 8883 with `--tls`. `--user` takes a username and
`--pass-env` takes the *name of an environment variable* to read the password out of, so it
never appears in `ps` output or in shell history. TLS is `--tls`, with `--ca` for a private
site certificate authority, `--cert` and `--cert-key` for mutual TLS, and `--insecure` to
skip verification — which warns loudly about what you just gave up.

`--topic` is repeatable and sets what is *subscribed* to. `--filter` is a different thing: a
client-side narrowing that applies only to what `--watch` prints.

## It cannot write

The tool sends exactly five packet types: CONNECT, SUBSCRIBE, PUBACK (only for a received
QoS 1 message, because the protocol requires it), PINGREQ and DISCONNECT. There is no
PUBLISH encoder in the file at all, so it cannot write a topic, cannot clear or overwrite a
retained message, and cannot register a will. Every outbound byte goes through `send()`,
which refuses any packet type outside that list.

```
$ python3 mqtt-tap.py --self-check
6 checks, 0 failed
```

That runs the refusal and the remaining-length codec and prints the result, so the claim is
checkable in two seconds rather than taken on trust.

It connects with a clean session and a distinctive random client id (`mqtt-tap-<hex>`), so
it cannot take over a running client's session or make the broker drop one. A wildcard
subscription is still not free: on a busy broker `#` for twenty seconds is real traffic, and
`$SYS` is deliberately withheld from wildcard output.

## What it implements

MQTT 3.1.1 (protocol level 4) on a raw socket: CONNECT/CONNACK, SUBSCRIBE/SUBACK, inbound
PUBLISH at QoS 0 and 1 with PUBACK, PINGREQ/PINGRESP keepalive, DISCONNECT. Remaining-length
varints are encoded and decoded to spec (1–4 bytes, 268435455 max) and the receive path is a
byte buffer, so a PUBLISH split across TCP reads and several PUBLISHes arriving in one read
are both handled.

A 5.0 broker's CONNACK is accepted too — a third byte is read as the MQTT 5 reason code and
the property block skipped — but that is the only 5.0 handling here. No properties are sent
or reported, and a broker that requires 5.0 will refuse the connection with "unsupported
protocol version", which the tool prints in words. QoS 2 is not implemented.

Three more things it does not do, each stated in `--help` as well. There is no session
resumption: every connection is a clean session, so a reconnect starts from nothing. No MQTT
5 properties are sent or reported. And Sparkplug B is handled by topic, not by payload —
`spBv1.0/...` topics are recognised by name and counted, and their protobuf payloads are
reported as binary with a byte count, never decoded. If you need the metric names inside a
Sparkplug payload, this is not the tool.

## Tests

```sh
tests/test-mqtt-tap.sh              # 130 assertions, 48s, all on 127.0.0.1
python3 mqtt-tap.py --self-check    # 6 checks, instant
```

Covered, deliberately awkwardly: a PUBLISH written one byte at a time and several PUBLISHes
in one read; a 27 kB payload reassembled byte for byte; a multi-byte remaining-length varint
cross-checked against a second implementation over 5,010 lengths; QoS 1 delivery with one
PUBACK each; every MQTT 3.1.1 connect-refusal code turned into a sentence; a broker that
refuses a topic filter, and one that accepts `#` and then sends nothing; an unanswered
keepalive; a broker that hangs up mid-window; non-ASCII topics and payloads; and `$SYS`
correctly withheld from a wildcard subscription. TLS was verified on loopback against a
certificate authority and certificate pair generated for the test: verification passing,
verification failing, and `--insecure`.

## Licence

MIT. See [LICENSE](LICENSE). Use it, fork it, ship it inside something you sell; no
attribution needed beyond the licence text.

## More

The [tool's page](https://plantroomlabs.com/tools/mqtt-tap/) has real terminal transcripts
from the fixture and the full blind-spot list. Its three siblings are
[bacnet-sweep](https://github.com/UsamaIqbal0304/bacnet-sweep),
[decoder-check](https://github.com/UsamaIqbal0304/decoder-check) and
[obix-mcp](https://github.com/UsamaIqbal0304/obix-mcp).

Written by [Plantroom Labs](https://plantroomlabs.com) — Niagara Framework engineering:
modules and drivers, bajaux widgets, PX graphics, station and controller work. Issues and
pull requests are read.
