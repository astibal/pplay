import io
import importlib.util
import json
import socket
import subprocess
import sys
import textwrap
import threading
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
        self.writes = []

    def send(self, data):
        self.writes.append(bytes(data))
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


def test_exact_fragment_sizes_are_used_for_stream_writes():
    repeater = pplay.Repeater(None, "")
    repeater.sock = RecordingSocket()
    repeater.whoami = "client"
    repeater.packets = [b"abcdefghij"]
    repeater.origins = {"client": [0], "server": []}
    repeater.fragments = {0: [1, 3, 2]}
    repeater.to_send = repeater.packets[0]

    repeater.send_to_send()

    assert repeater.sock.writes == [b"a", b"bcd", b"ef", b"ghij"]


def test_script_refuzz_is_repeatable_for_fresh_server_sessions(monkeypatch):
    class Script:
        packets = [b"client payload", b"server payload"]

    repeater = pplay.Repeater(None, "")
    repeater.fuzz = True
    monkeypatch.setattr(pplay.Features, "fuzz_magic", "repeatable")
    monkeypatch.setattr(pplay.Features, "fuzz_level", 128)
    monkeypatch.setattr(
        pplay.Features,
        "fuzz_prng",
        pplay.BytesGenerator("repeatable", use_hash=pplay.hashlib.sha256()),
    )

    repeater.scripter = Script()
    repeater.scripter_refuzz()
    first = list(repeater.packets)
    repeater.scripter = Script()
    repeater.scripter_refuzz()

    assert repeater.packets == first


def test_machine_reports_are_atomic_and_describe_failure(tmp_path):
    json_path = tmp_path / "report.json"
    junit_path = tmp_path / "report.xml"
    report = pplay.TestReport(str(json_path), str(junit_path))
    report.role = "client"
    report.mismatches = 1
    report.received_packets = 2
    report.write()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["result"] == "mismatch"
    assert data["payload_mismatches"] == 1
    assert "failure" in junit_path.read_text(encoding="utf-8")


def test_orchestrator_removes_parent_options_and_numbers_reports():
    result = pplay._orchestrated_child_args(
        [
            "--client",
            "127.0.0.1:80",
            "--parallel-runs=3",
            "--parallel-start-delays=0,1",
            "--repeat",
            "4",
            "--report-json=result.json",
        ],
        parallel_index=2,
        repeat_index=3,
    )

    assert result == [
        "--client",
        "127.0.0.1:80",
        "--report-json=result.p02-r003.json",
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
    server_report = tmp_path / "server.json"
    client_report = tmp_path / "client.json"
    common = [
        sys.executable,
        str(Path(pplay.__file__).resolve()),
        "--script",
        str(script),
        "--test",
        "--die-after",
        "10",
        "--split",
        "0:1,2",
    ]

    server = subprocess.Popen(
        common + ["--report-json", str(server_report), "--server", "127.0.0.1:%d" % port],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(0.25)
        client = subprocess.run(
            common + ["--report-json", str(client_report), "--client", "127.0.0.1:%d" % port],
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
    assert json.loads(client_report.read_text(encoding="utf-8"))["result"] == "pass"
    assert json.loads(server_report.read_text(encoding="utf-8"))["result"] == "pass"


def test_test_mode_reports_transport_failure(tmp_path):
    port = _unused_tcp_port()
    report_path = tmp_path / "transport-error.json"

    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            "examples/simple1_pps.py",
            "--test",
            "--report-json",
            str(report_path),
            "--client",
            "127.0.0.1:%d" % port,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )

    assert result.returncode == 4, result.stdout
    assert json.loads(report_path.read_text(encoding="utf-8"))["result"] == "transport_error"


def test_parallel_repeat_orchestrator(tmp_path):
    expected_connections = 4
    received = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(expected_connections)
    listener.settimeout(10)
    port = listener.getsockname()[1]

    def receive_all():
        try:
            for _ in range(expected_connections):
                connection, _address = listener.accept()
                with connection:
                    received.append(connection.recv(1024))
        finally:
            listener.close()

    server_thread = threading.Thread(target=receive_all)
    server_thread.start()
    script = tmp_path / "client-only.py"
    script.write_text(
        textwrap.dedent(
            """
            class PPlayScript:
                def __init__(self, pplay, args=None):
                    self.pplay = pplay
                    self.packets = [b"parallel-test"]
                    self.origins = {"client": [0], "server": []}
                    self.server_port = 0
                    self.custom_sport = None
                    self.ssl_cert = self.ssl_key = None
                    self.ssl_ca_cert = self.ssl_ca_key = None
            """
        ),
        encoding="utf-8",
    )
    report_dir = tmp_path / "reports"
    summary_path = tmp_path / "summary.json"

    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            str(script),
            "--test",
            "--client",
            "127.0.0.1:%d" % port,
            "--parallel-runs",
            "2",
            "--parallel-start-delays",
            "0.2",
            "--repeat",
            "2",
            "--repeat-interval",
            "0.01",
            "--report-dir",
            str(report_dir),
            "--parallel-summary-json",
            str(summary_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
    )
    server_thread.join(timeout=10)

    assert result.returncode == 0, result.stdout
    assert sorted(received) == [b"parallel-test"] * expected_connections
    assert "[P1/2 R1/2]" in result.stdout
    assert "[P2/2 R2/2]" in result.stdout
    assert len(list(report_dir.glob("*.json"))) == expected_connections
    assert len(list(report_dir.glob("*.xml"))) == expected_connections
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["result"] == "pass"
    assert len(summary["runs"]) == expected_connections
    first_starts = {
        run["parallel_index"]: run["started_after_ms"]
        for run in summary["runs"]
        if run["repeat_index"] == 1
    }
    assert first_starts[2] - first_starts[1] >= 150


def test_start_delay_parser_accepts_lists_commas_and_reuses_last_value():
    parser = pplay.argparse.ArgumentParser()

    delays = pplay._parse_start_delays(["0.1,0.2", "0.3"], parser)

    assert delays == [0.1, 0.2, 0.3]
    assert [delays[min(index, len(delays) - 1)] for index in range(5)] == [
        0.1, 0.2, 0.3, 0.3, 0.3,
    ]


def test_fail_fast_stops_future_repeats(tmp_path):
    port = _unused_tcp_port()
    summary_path = tmp_path / "fail-fast.json"

    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            "examples/simple1_pps.py",
            "--test",
            "--client",
            "127.0.0.1:%d" % port,
            "--repeat",
            "3",
            "--repeat-interval",
            "0.5",
            "--parallel-fail-fast",
            "--parallel-summary-json",
            str(summary_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert result.returncode == 1, result.stdout
    assert summary["result"] == "fail"
    assert len(summary["runs"]) == 1
    assert summary["runs"][0]["returncode"] == 4


def test_fail_fast_shared_signal_cancels_delayed_workers(tmp_path):
    port = _unused_tcp_port()
    summary_path = tmp_path / "shared-stop.json"
    started = time.monotonic()

    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            "examples/simple1_pps.py",
            "--test",
            "--client",
            "127.0.0.1:%d" % port,
            "--parallel-runs",
            "2",
            "--parallel-start-delays",
            "5",
            "--parallel-fail-fast",
            "--parallel-summary-json",
            str(summary_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )
    elapsed = time.monotonic() - started

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert result.returncode == 1, result.stdout
    assert elapsed < 5
    assert len(summary["runs"]) == 1
    assert summary["runs"][0]["parallel_index"] == 1


def test_repeat_interval_delays_next_run(tmp_path):
    port = _unused_tcp_port()
    summary_path = tmp_path / "repeat-interval.json"

    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            "examples/simple1_pps.py",
            "--test",
            "--client",
            "127.0.0.1:%d" % port,
            "--repeat",
            "2",
            "--repeat-interval",
            "0.25",
            "--parallel-summary-json",
            str(summary_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert result.returncode == 1, result.stdout
    assert len(summary["runs"]) == 2
    first, second = summary["runs"]
    assert second["started_after_ms"] >= first["started_after_ms"] + first["duration_ms"] + 200


def test_parallel_timeout_kills_stalled_replay(tmp_path):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    release_server = threading.Event()

    def stalled_server():
        connection, _address = listener.accept()
        with connection:
            connection.recv(1024)
            release_server.wait(5)
        listener.close()

    server_thread = threading.Thread(target=stalled_server, daemon=True)
    server_thread.start()
    summary_path = tmp_path / "timeout.json"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            "examples/simple1_pps.py",
            "--test",
            "--client",
            "127.0.0.1:%d" % port,
            "--parallel-timeout",
            "1.5",
            "--parallel-summary-json",
            str(summary_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )
    release_server.set()
    server_thread.join(timeout=5)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert result.returncode == 1, result.stdout
    assert summary["runs"][0]["timed_out"] is True
    assert summary["runs"][0]["returncode"] == 3
    assert "orchestrator timeout" in result.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["--parallel-runs", "0"],
        ["--repeat", "0"],
        ["--repeat-interval", "-1"],
        ["--parallel-timeout", "0"],
    ],
)
def test_orchestration_rejects_invalid_counts_and_intervals(arguments):
    result = subprocess.run(
        [sys.executable, str(Path(pplay.__file__).resolve())] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2


def test_repeat_and_parallel_options_are_client_only():
    result = subprocess.run(
        [
            sys.executable,
            str(Path(pplay.__file__).resolve()),
            "--script",
            "examples/simple1_pps.py",
            "--server",
            "19091",
            "--repeat",
            "2",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert "client-only" in result.stdout
