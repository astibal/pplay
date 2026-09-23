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

## Useful options

```text
--auto SECONDS     send aligned payloads automatically
--noauto           require interactive confirmation
--exitoneot        exit at the end of the conversation
--exitondiff       fail when received data differs
--nostdin          disable interactive input
--fuzz LEVEL       deterministically taint payload bytes
--scatter          split stream payloads into smaller writes
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
