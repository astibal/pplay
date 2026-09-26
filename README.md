# Pplay

Pplay replays **application payloads** from a network capture over a new
connection.

It deliberately ignores original TCP sequence numbers, timing, and most
lower-layer details. This makes it useful when a capture must be replayed
through a proxy, a different network path, or a small test lab where
packet-for-packet replay would not work.

Its most useful features are:

- export a PCAP flow into an editable **PPlayScript**;
- change payloads dynamically with Python hooks;
- replay the client and server sides over TCP, TLS, UDP, or SCTP;
- package Pplay and replay data into one self-contained Python file;
- deploy and run that package on a remote host over SSH without installing Pplay there.

```text
capture.pcapng
      │  --export
      ▼
 replay.py (PPlayScript)
      │  --pack / --remote-ssh
      ▼
local or remote replay
```

## Contents

- [Quick start with a PCAP](#quick-start-with-a-pcap)
- [PPlayScript](#pplayscript)
- [Self-contained replay](#self-contained-replay)
- [SSH self-deployment](#ssh-self-deployment)
- [TLS and STARTTLS](#tls-and-starttls)
- [Automated testing](#automated-testing)
- [Parallel and repeated clients](#parallel-and-repeated-clients)
- [Exact stream fragmentation](#exact-stream-fragmentation)
- [Useful options](#useful-options)
- [Legacy SMCAP support](#legacy-smcap-support)

## Installation

```shell
python3 -m pip install pplay
```

The installed command is `pplay.py`:

```shell
pplay.py --version
pplay.py --help
```

Pplay is primarily developed and tested on Linux.

## How replay works

A capture contains both directions of a conversation. Pplay extracts their
payloads and keeps their order:

```text
client payload  ──▶  server
client          ◀──  server payload
client payload  ──▶  server
```

Normally, run one Pplay instance as the server and another as the client.
Both instances use the same capture or PPlayScript. Each side sends only the
payloads assigned to its role and checks received data against the expected
conversation.

Pplay reports received data as matching, modified, or different. By default it
offers each aligned payload for several seconds before sending it automatically.
Use `--auto`, `--noauto`, or the interactive commands to change that behavior.

## Quick start with a PCAP

First, list usable flows:

```shell
pplay.py --pcap capture.pcapng --list
```

Select a connection by its source endpoint, for example `10.0.0.20:59471`.

Start the replay server:

```shell
pplay.py \
  --pcap capture.pcapng \
  --connection 10.0.0.20:59471 \
  --server 127.0.0.1:9000
```

In another terminal, start the client:

```shell
pplay.py \
  --pcap capture.pcapng \
  --connection 10.0.0.20:59471 \
  --client 127.0.0.1:9000
```

For a non-interactive one-shot replay, add:

```text
--auto 0.1 --nostdin --exitoneot --exitondiff
```

## PPlayScript

A PPlayScript is an editable Python representation of a conversation.
It removes the capture dependency and provides hooks for:

- dynamic payload generation;
- state tracking;
- STARTTLS;
- authentication tokens and timestamps;
- fuzzing or protocol-specific behavior.

Export a selected PCAP flow:

```shell
pplay.py \
  --pcap capture.pcapng \
  --connection 10.0.0.20:59471 \
  --export replay.py
```

Run the exported script instead of the capture:

```shell
pplay.py --script replay.py --server 127.0.0.1:9000
pplay.py --script replay.py --client 127.0.0.1:9000
```

### Script structure

Payloads are bytes. `origins` maps each role to indexes in the shared packet list:

```python
class PPlayScript:
    def __init__(self, pplay, args=None):
        self.pplay = pplay
        self.args = args

        self.packets = [
            b"EHLO client.example\r\n",
            b"250 server.example\r\n",
            b"QUIT\r\n",
            b"221 bye\r\n",
        ]
        self.origins = {
            "client": [0, 2],
            "server": [1, 3],
        }
        self.server_port = 25
        self.custom_sport = None
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_cert = None
        self.ssl_ca_key = None

    def before_send(self, role, index, data):
        # Return bytes or str to replace the payload, or None to keep it.
        if role == "client" and index == 0:
            return b"EHLO dynamic.example\r\n"
        return None

    def after_received(self, role, index, data):
        # Observe received data and update script state if needed.
        return None

    def after_send(self, role, index, data):
        return None
```

An optional string can be passed to the script constructor:

```shell
pplay.py --script replay.py --script-args test-run-42 --client 127.0.0.1:9000
```

See the
[example scripts](https://github.com/astibal/pplay/tree/master/examples)
for additional conversations.

## Self-contained replay

`--pack` creates one executable Python file containing:

- the Pplay engine;
- the selected payload sequence;
- embedded certificates or keys when explicitly supplied.

Create a package:

```shell
pplay.py \
  --pcap capture.pcapng \
  --connection 10.0.0.20:59471 \
  --pack /tmp/packed-pplay.py
```

Run its server side locally:

```shell
python3 /tmp/packed-pplay.py \
  --script + \
  --server 9000 \
  --auto 0.1 \
  --nostdin \
  --exitoneot
```

The `+` means “use the PPlayScript embedded in this file.”

## SSH self-deployment

The packed file can be streamed to a host that has Python 3 but does not have Pplay installed:

```shell
ssh lab-server python3 - \
  --script + \
  --server 9000 \
  --auto 0.1 \
  --nostdin \
  --exitoneot \
  < /tmp/packed-pplay.py
```

Pplay can also perform packing, transfer, and execution itself with `--remote-ssh`.

Deploy the server side remotely:

```shell
pplay.py \
  --pcap capture.pcapng \
  --connection 10.0.0.20:59471 \
  --server 9000 \
  --remote-ssh 192.0.2.20:22 \
  --remote-ssh-user lab \
  --auto 0.1 \
  --exitoneot
```

Then run the matching client side locally:

```shell
pplay.py \
  --pcap capture.pcapng \
  --connection 10.0.0.20:59471 \
  --client 192.0.2.20:9000 \
  --auto 0.1 \
  --nostdin \
  --exitoneot
```

SSH agent or key authentication is recommended. `--remote-ssh-password` exists
for controlled test environments, but command-line passwords may be exposed
through shell history or process inspection.

The remote host needs only Python for a basic packed replay. Features used by
a custom script may require their corresponding Python libraries.

## TLS and STARTTLS

Use `--ssl` to wrap a connection in TLS from the beginning. A server needs
either an explicit certificate and key or a CA pair for dynamic certificates:

```shell
pplay.py --script replay.py --server 9443 --ssl --cert server.pem --key server.key
pplay.py --script replay.py --client 127.0.0.1:9443 --ssl --sni server.example
```

A PPlayScript can switch an existing connection to TLS by calling:

```python
self.pplay.starttls()
```

from the appropriate `before_send` or `after_send` hook. The repository contains
a [STARTTLS example](https://github.com/astibal/pplay/blob/master/examples/smtp_starttls_pps.py).

## Automated testing

`--test` is a strict, non-interactive replay preset. It enables fast automatic
sending, exits at end of transmission or on a payload mismatch, and disables
colors and hexdumps.

Each endpoint can write an atomic JSON or JUnit report. Use a different output
file for the client and server:

```shell
pplay.py --script replay.py --test \
  --report-json server.json --report-junit server.xml \
  --server 127.0.0.1:9000

pplay.py --script replay.py --test \
  --report-json client.json --report-junit client.xml \
  --client 127.0.0.1:9000
```

The JSON result is one of `pass`, `mismatch`, `timeout`, `transport_error`, or
`incomplete` and contains packet counts, byte counts, mismatch count, role, and
duration. In test mode the primary exit codes are stable:

```text
0  replay passed
2  payload mismatch or invalid CLI usage
3  death-timer timeout
4  transport error
```

## Parallel and repeated clients

Client runs can be repeated inside several parallel workers:

```shell
pplay.py --script replay.py --test --client 127.0.0.1:9000 \
  --parallel-runs 4 \
  --parallel-start-delays 0 0.5 2 \
  --repeat 10 \
  --repeat-interval 1
```

This creates 4 workers with 10 sequential replays each, for a total of 40
client connections:

```text
client orchestrator
    |
    +-- worker P1: R1 -> R2 -> ... -> R10
    +-- worker P2: R1 -> R2 -> ... -> R10
    +-- worker P3: R1 -> R2 -> ... -> R10
    `-- worker P4: R1 -> R2 -> ... -> R10
```

### Worker start timing

Start delays are measured from the start of one worker to the start of the next:

```text
P1 --0s--> P2 --0.5s--> P3 --2s--> P4
```

When fewer delays than required are supplied, the last value is reused. For
example, five workers with `--parallel-start-delays 1 2` start as follows:

```text
P1 --1s--> P2 --2s--> P3 --2s--> P4 --2s--> P5
```

Comma-separated values such as `--parallel-start-delays 0,0.5,2` are accepted
too.

### Isolation and output

Each worker repeats its client replay sequentially. Workers share a stop signal,
but every replay runs in an isolated child process so socket, TLS, fuzz, scatter,
script, and report state cannot leak between concurrent runs:

```text
shared stop event
    |
    +-- worker thread P1 -- isolated Pplay process R1, R2, ...
    +-- worker thread P2 -- isolated Pplay process R1, R2, ...
    `-- worker thread P3 -- isolated Pplay process R1, R2, ...
```

`--repeat-interval` is measured after a replay finishes and before that worker
starts its next replay. Every output line is labelled with its worker and repeat:

```text
[P2/4 R3/10] # ... has been sent (128 bytes)
```

Without parallel or repeat options, Pplay uses its original direct execution
path and does not create an orchestrator or child replay process.

### Failure handling

Useful orchestration controls:

```text
--parallel-fail-fast       stop delayed starts and future repeats after a failure
--parallel-timeout SEC     maximum duration of one replay
--report-dir DIR           write one JSON and JUnit report per replay
--parallel-summary-json F  write an aggregate atomic JSON report
```

Fail-fast uses the shared stop event. Replays that are already running are
allowed to finish, while delayed worker starts and future repeats are cancelled.
`--parallel-timeout` applies separately to each replay and is independent of
Pplay's internal `--die-after` safety timer.

### Reports

When `--report-json` or `--report-junit` is used directly, its filename is
automatically extended with `.pNN-rNNN` for orchestrated runs.

`--report-dir results` creates a JSON and JUnit file for every replay:

```text
results/
|-- pplay-p01-r001.json
|-- pplay-p01-r001.xml
|-- pplay-p01-r002.json
|-- pplay-p01-r002.xml
`-- pplay-p02-r001.json
```

The aggregate summary records the start offset, duration, timeout state, and
return code of every replay:

```json
{
  "result": "pass",
  "parallel_runs": 2,
  "repeat": 2,
  "duration_ms": 4381,
  "runs": [
    {
      "parallel_index": 1,
      "repeat_index": 1,
      "started_after_ms": 0,
      "duration_ms": 2091,
      "timed_out": false,
      "returncode": 0
    }
  ]
}
```

Client orchestration is intentionally not available in server mode. A Pplay
server remains a single replay endpoint; use a concurrent origin server when
testing many simultaneous clients.

## Exact stream fragmentation

`--split` controls individual socket writes for a global packet index. Values
are chunk sizes; any remaining payload is sent as the final chunk:

```shell
# Packet 0: write 1 byte, then 4, then 17, then the remainder.
pplay.py --script replay.py --split 0:1,4,17 --client 127.0.0.1:9000
```

This is deterministic and takes precedence over random `--scatter` for that
packet. UDP datagrams are never fragmented.

A PPlayScript can carry the same plan:

```python
self.fragments = {
    0: [1, 4, 17],
    3: [5, 5, 1, 128],
}
```

CLI `--split` entries override matching script entries.

## Useful options

```text
--auto SECONDS     send aligned payloads automatically
--noauto           require interactive confirmation
--exitoneot        exit at the end of the conversation
--exitondiff       fail when received data differs
--nostdin          disable interactive input
--fuzz LEVEL       deterministically taint payload bytes
--scatter          split stream payloads into smaller writes
--split I:SIZES    split packet I into deterministic stream writes
--test             strict non-interactive replay preset
--report-json FILE write an atomic JSON test report
--report-junit FILE write an atomic JUnit XML test report
--parallel-runs N   run N client workers concurrently
--parallel-start-delays T... delay consecutive worker starts
--repeat N          repeat each client worker N times
--repeat-interval T wait after a replay before its next repeat
--parallel-timeout T limit each orchestrated replay
--parallel-fail-fast stop scheduling work after the first failure
--report-dir DIR     write per-replay JSON and JUnit reports
--parallel-summary-json FILE write an aggregate JSON report
--socks HOST:PORT  connect the client through SOCKS5
--tcp / --udp      override the transport detected in the capture
```

Interactive commands:

```text
Enter / y            send
s                    skip
c / l / x            send CR / LF / CRLF
i                    toggle autosend
r/old/new/count      replace payload content
```

## Legacy SMCAP support

SMCAP is the historical textual capture format produced by Smithproxy.
Pplay still supports `--smcap` and the `smcap2pcap` compatibility utility,
but new workflows should generally start from PCAP/PCAPNG or an exported
PPlayScript.

```shell
pplay.py --smcap legacy.smcap --list
pplay.py --smcap legacy.smcap --export replay.py
```

## Project links

- Source and issues: <https://github.com/astibal/pplay>
- PyPI: <https://pypi.org/project/pplay/>
- License: GNU Library General Public License 2.0 or later
