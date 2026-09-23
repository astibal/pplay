import io
import importlib.util
import sys
from pathlib import Path

import pytest

import pplay


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
