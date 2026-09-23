import io
import importlib.util
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import pplay


def _unused_tcp_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize(
    "example",
    ["simple1_pps.py", "simple2_pps.py", "smtp_starttls_pps.py"],
)
def test_pplayscript_examples_use_current_payload_format(example):
    path = Path("examples") / example
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    script = module.PPlayScript(pplay.Repeater(None, ""))

    assert script.packets
    assert all(isinstance(packet, bytes) for packet in script.packets)
    assert len(script.packets) == sum(len(indexes) for indexes in script.origins.values())
    assert all(
        hasattr(script, name)
        for name in ("ssl_cert", "ssl_key", "ssl_ca_cert", "ssl_ca_key")
    )


def test_smcap_sample_loads():
    repeater = pplay.Repeater("samples/smcap_sample.smcap", "")

    repeater.read_smcap("", "")

    assert repeater.packets
    assert len(repeater.packets) == (
        len(repeater.origins["client"]) + len(repeater.origins["server"])
    )


def test_smcap_flushes_last_packet_at_eof(tmp_path):
    capture = tmp_path / "no-trailing-separator.smcap"
    capture.write_text(
        "+1: 192.0.2.1:12345-192.0.2.2:80\n"
        ">[0]  48 65 6C 6C 6F",
        encoding="ascii",
    )
    repeater = pplay.Repeater(str(capture), "")

    repeater.read_smcap("", "")

    assert repeater.packets == [b"Hello"]
    assert repeater.origins["client"] == [0]


class FragmentedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.blocking = None

    def pending(self):
        return len(self.chunks[0]) if self.chunks else 0

    def recv(self, size):
        chunk = self.chunks.pop(0)
        assert len(chunk) <= size
        return chunk

    def setblocking(self, value):
        self.blocking = value


def test_tls_read_accumulates_fragmented_payload(monkeypatch):
    monkeypatch.setattr(pplay.Features, "have_ssl", True)
    repeater = pplay.Repeater(None, "")
    repeater.use_ssl = True
    repeater.sock = FragmentedSocket([b"ab", b"cd", b"ef"])

    assert repeater.read(6) == b"abcdef"


class ClosedSocket:
    def send(self, _data):
        return 0


def test_zero_length_socket_write_fails_instead_of_looping():
    repeater = pplay.Repeater(None, "")
    repeater.sock = ClosedSocket()

    with pytest.raises(ConnectionError, match="broken"):
        repeater.write(b"payload")


class RecordingSocket:
    def __init__(self):
        self.data = bytearray()

    def send(self, data):
        self.data.extend(data)
        return len(data)


@pytest.mark.parametrize(
    ("command", "expected"),
    [("c", b"\r"), ("l", b"\n"), ("x", b"\r\n")],
)
def test_manual_line_ending_commands_send_bytes(command, expected):
    repeater = pplay.Repeater(None, "")
    repeater.sock = RecordingSocket()

    repeater.process_command(command, "clx")

    assert bytes(repeater.sock.data) == expected


def test_manual_replace_preserves_binary_payload():
    repeater = pplay.Repeater(None, "")

    result = repeater.cmd_replace("r/GET/POST/1", b"\xffGET / HTTP/1.0\r\n")

    assert result == b"\xffPOST / HTTP/1.0\r\n"


def test_new_data_stops_on_blank_line(monkeypatch):
    repeater = pplay.Repeater(None, "")
    monkeypatch.setattr(sys, "stdin", io.StringIO("first\nsecond\n\nafter\n"))

    result = repeater.cmd_newdata("N", b"")

    assert result == b"first\r\nsecond\r\n"


def test_script_hooks_modify_manual_send():
    events = []

    class Script:
        def before_send(self, role, index, data):
            events.append(("before", role, index, data))
            return "modified"

        def after_send(self, role, index, data):
            events.append(("after", role, index, data))

    repeater = pplay.Repeater(None, "")
    repeater.sock = RecordingSocket()
    repeater.scripter = Script()
    repeater.whoami = "client"
    repeater.to_send = b"original"

    repeater.send_to_send()

    assert bytes(repeater.sock.data) == b"modified"
    assert [event[:3] for event in events] == [
        ("before", "client", 0),
        ("after", "client", 0),
    ]


def test_export_accepts_ca_argument_names(tmp_path, monkeypatch):
    exported = tmp_path / "exported.py"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pplay.py",
            "--smcap",
            "samples/smcap_sample.smcap",
            "--export",
            str(exported),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        pplay.main()

    assert exc.value.code == 0
    assert exported.is_file()


def test_script_replay_end_to_end(tmp_path):
    script = tmp_path / "conversation.py"
    script.write_text(
        textwrap.dedent(
            """
            class PPlayScript:
                def __init__(self, pplay, args=None):
                    self.pplay = pplay
                    self.args = args
                    self.packets = [b"PING\\n", b"PONG\\n"]
                    self.origins = {"client": [0], "server": [1]}
                    self.server_port = 0
                    self.custom_sport = None
                    self.ssl_cert = None
                    self.ssl_key = None
                    self.ssl_ca_cert = None
                    self.ssl_ca_key = None
            """
        ),
        encoding="utf-8",
    )
    port = _unused_tcp_port()
    common = [
        sys.executable,
        str(Path(pplay.__file__).resolve()),
        "--script",
        str(script),
        "--auto",
        "0.01",
        "--nostdin",
        "--exitoneot",
        "--exitondiff",
        "--die-after",
        "10",
        "--nocolor",
        "--nohex",
    ]

    server = subprocess.Popen(
        common + ["--server", "127.0.0.1:%d" % port],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(0.25)
        client = subprocess.run(
            common + ["--client", "127.0.0.1:%d" % port],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
        server_output, _ = server.communicate(timeout=15)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()

    assert client.returncode == 0, client.stdout
    assert server.returncode == 0, server_output
    assert "has been sent (5 bytes)" in client.stdout
    assert "has been sent (5 bytes)" in server_output
