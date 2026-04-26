import socket
import pytest
import psutil
from unittest.mock import patch, MagicMock

from src.collector import get_connections


REQUIRED_KEYS = {
    "pid", "process_name", "process_path",
    "local_ip", "local_port",
    "remote_ip", "remote_port",
    "protocol", "status",
}


def _make_proc(pid=1234, name="chrome.exe"):
    proc = MagicMock()
    proc.info = {"pid": pid, "name": name}
    return proc


def _make_conn(
    family=socket.AF_INET,
    sock_type=socket.SOCK_STREAM,
    laddr=("127.0.0.1", 8080),
    raddr=("8.8.8.8", 443),
    status="ESTABLISHED",
    pid=1234,
):
    conn = MagicMock()
    conn.family = family
    conn.type = sock_type
    conn.laddr = MagicMock(ip=laddr[0], port=laddr[1]) if laddr else None
    conn.raddr = MagicMock(ip=raddr[0], port=raddr[1]) if raddr else None
    conn.status = status
    conn.pid = pid
    return conn


class TestGetConnections:

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_returns_list(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc()]
        mock_net.return_value = [_make_conn()]
        mock_proc.return_value.exe.return_value = "C:/chrome.exe"

        result = get_connections()

        assert isinstance(result, list)

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_each_entry_has_required_keys(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc()]
        mock_net.return_value = [_make_conn()]
        mock_proc.return_value.exe.return_value = "C:/chrome.exe"

        result = get_connections()

        assert len(result) == 1
        assert REQUIRED_KEYS.issubset(result[0].keys())

    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_empty_connections_returns_empty_list(self, mock_iter, mock_net):
        mock_iter.return_value = []
        mock_net.return_value = []

        result = get_connections()

        assert result == []

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_tcp_protocol_mapped_correctly(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc()]
        mock_net.return_value = [_make_conn(family=socket.AF_INET, sock_type=socket.SOCK_STREAM)]
        mock_proc.return_value.exe.return_value = "C:/chrome.exe"

        result = get_connections()

        assert result[0]["protocol"] == "tcp"

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_udp_protocol_mapped_correctly(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc()]
        mock_net.return_value = [_make_conn(family=socket.AF_INET, sock_type=socket.SOCK_DGRAM, status="")]
        mock_proc.return_value.exe.return_value = "C:/chrome.exe"

        result = get_connections()

        assert result[0]["protocol"] == "udp"

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_missing_raddr_gives_empty_remote_fields(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc()]
        mock_net.return_value = [_make_conn(raddr=None)]
        mock_proc.return_value.exe.return_value = "C:/chrome.exe"

        result = get_connections()

        assert result[0]["remote_ip"] == ""
        assert result[0]["remote_port"] is None

    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_none_pid_gives_unknown_process_and_path(self, mock_iter, mock_net):
        mock_iter.return_value = []
        mock_net.return_value = [_make_conn(pid=None)]

        result = get_connections()

        assert result[0]["process_name"] == "unknown"
        assert result[0]["process_path"] == "unknown"

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_access_denied_on_exe_gives_unknown_path(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc(pid=999, name="svchost.exe")]
        mock_net.return_value = [_make_conn(pid=999)]
        mock_proc.return_value.exe.side_effect = psutil.AccessDenied(pid=999)

        result = get_connections()

        assert result[0]["process_path"] == "unknown"

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_process_name_resolved_from_pid(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc(pid=42, name="firefox.exe")]
        mock_net.return_value = [_make_conn(pid=42)]
        mock_proc.return_value.exe.return_value = "C:/firefox.exe"

        result = get_connections()

        assert result[0]["process_name"] == "firefox.exe"

    @patch("psutil.Process")
    @patch("psutil.net_connections")
    @patch("psutil.process_iter")
    def test_unknown_protocol_labeled_other(self, mock_iter, mock_net, mock_proc):
        mock_iter.return_value = [_make_proc()]
        # Use a family/type combo not in _PROTO_MAP
        mock_net.return_value = [_make_conn(family=999, sock_type=999)]
        mock_proc.return_value.exe.return_value = "C:/chrome.exe"

        result = get_connections()

        assert result[0]["protocol"] == "other"
