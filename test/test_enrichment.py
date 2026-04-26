import json
import pytest
from unittest.mock import patch, MagicMock

from src.enrichment import enrich, enrich_dns, enrich_logs


KNOWN_PORTS = {
    "443": {"service": "HTTPS",       "suspicious": False},
    "4444": {"service": "Meterpreter", "suspicious": True},
}

KNOWN_PROCESSES = {
    "chrome.exe": {
        "description": "Google Chrome browser",
        "expected_ports": [80, 443],
    }
}


# ---------------------------------------------------------------------------
# enrich()
# ---------------------------------------------------------------------------

class TestEnrich:

    def test_known_port_sets_service_name(self):
        conn = {"remote_port": 443, "process_name": "other.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["service_name"] == "HTTPS"

    def test_unknown_port_defaults_to_unknown_service(self):
        conn = {"remote_port": 9999, "process_name": "other.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["service_name"] == "Unknown"
        assert result["port_suspicious"] is False

    def test_suspicious_port_flagged(self):
        conn = {"remote_port": 4444, "process_name": "other.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["port_suspicious"] is True

    def test_known_process_sets_metadata(self):
        conn = {"remote_port": 443, "process_name": "chrome.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["process_known"] is True
        assert result["process_description"] == "Google Chrome browser"

    def test_unknown_process_defaults_to_not_known(self):
        conn = {"remote_port": 443, "process_name": "mystery.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["process_known"] is False
        assert result["process_description"] is None
        assert result["port_mismatch"] is False

    def test_port_mismatch_detected_for_known_process(self):
        conn = {"remote_port": 8080, "process_name": "chrome.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["port_mismatch"] is True

    def test_no_port_mismatch_on_expected_port(self):
        conn = {"remote_port": 443, "process_name": "chrome.exe"}
        result = enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert result["port_mismatch"] is False

    def test_original_connection_dict_not_mutated(self):
        conn = {"remote_port": 443, "process_name": "chrome.exe"}
        original = dict(conn)
        enrich(conn, KNOWN_PORTS, KNOWN_PROCESSES)
        assert conn == original


# ---------------------------------------------------------------------------
# enrich_dns()
# ---------------------------------------------------------------------------

class TestEnrichDns:

    @patch("src.enrichment.IPWhois")
    def test_cache_miss_calls_ipwhois_and_stores_result(self, mock_ipwhois):
        mock_ipwhois.return_value.lookup_rdap.return_value = {"asn_description": "Google LLC"}
        conn = {"remote_ip": "8.8.8.8"}
        cache = {}

        result = enrich_dns(conn, cache)

        mock_ipwhois.assert_called_once_with("8.8.8.8")
        assert result["dns_owner"] == "Google LLC"
        assert cache["8.8.8.8"] == "Google LLC"

    @patch("src.enrichment.IPWhois")
    def test_cache_hit_skips_ipwhois(self, mock_ipwhois):
        conn = {"remote_ip": "8.8.8.8"}
        cache = {"8.8.8.8": "Google LLC"}

        result = enrich_dns(conn, cache)

        mock_ipwhois.assert_not_called()
        assert result["dns_owner"] == "Google LLC"

    @patch("src.enrichment.IPWhois")
    def test_ipwhois_failure_stores_none(self, mock_ipwhois):
        mock_ipwhois.return_value.lookup_rdap.side_effect = Exception("network timeout")
        conn = {"remote_ip": "1.2.3.4"}
        cache = {}

        result = enrich_dns(conn, cache)

        assert result["dns_owner"] is None
        assert cache["1.2.3.4"] is None

    def test_empty_ip_skips_lookup_and_adds_no_dns_owner(self):
        conn = {"remote_ip": ""}
        cache = {}

        result = enrich_dns(conn, cache)

        assert "dns_owner" not in result
        assert cache == {}

    @patch("src.enrichment.IPWhois")
    def test_pbar_advanced_on_every_call(self, mock_ipwhois):
        mock_ipwhois.return_value.lookup_rdap.return_value = {"asn_description": "ACME"}
        pbar = MagicMock()
        conn = {"remote_ip": "1.2.3.4"}

        enrich_dns(conn, {}, pbar)

        pbar.update.assert_called_once_with(1)

    @patch("src.enrichment.IPWhois")
    def test_pbar_advanced_even_with_empty_ip(self, mock_ipwhois):
        pbar = MagicMock()
        conn = {"remote_ip": ""}

        enrich_dns(conn, {}, pbar)

        pbar.update.assert_called_once_with(1)

    @patch("src.enrichment.IPWhois")
    def test_pbar_postfix_shows_cached_on_hit(self, mock_ipwhois):
        pbar = MagicMock()
        conn = {"remote_ip": "1.2.3.4"}
        cache = {"1.2.3.4": "Google LLC"}

        enrich_dns(conn, cache, pbar)

        postfix_calls = [str(c) for c in pbar.set_postfix_str.call_args_list]
        assert any("cached" in c for c in postfix_calls)


# ---------------------------------------------------------------------------
# enrich_logs()
# ---------------------------------------------------------------------------

class TestEnrichLogs:

    def test_enriched_file_is_created(self, tmp_path, monkeypatch):
        log_data = [{"remote_ip": "1.2.3.4", "pid": 1}, {}]
        (tmp_path / "log-current.txt").write_text(json.dumps(log_data))
        monkeypatch.setattr("src.enrichment.path", tmp_path)

        with patch("src.enrichment.reverse_dns_search_dest_ips") as mock_rdns, \
             patch("shutil.copy"):
            mock_rdns.return_value = (["1.2.3.4"], ["Google LLC"])
            enrich_logs()

        assert (tmp_path / "log-enriched-current.txt").exists()

    def test_enriched_file_contains_dns_owner(self, tmp_path, monkeypatch):
        log_data = [{"remote_ip": "1.2.3.4", "pid": 1}, {}]
        (tmp_path / "log-current.txt").write_text(json.dumps(log_data))
        monkeypatch.setattr("src.enrichment.path", tmp_path)

        with patch("src.enrichment.reverse_dns_search_dest_ips") as mock_rdns, \
             patch("shutil.copy"):
            mock_rdns.return_value = (["1.2.3.4"], ["Google LLC"])
            enrich_logs()

        content = (tmp_path / "log-enriched-current.txt").read_text()
        assert "enriched_dns_owner" in content
        assert "Google LLC" in content

    def test_enrich_logs_calls_reverse_dns_with_log_name(self, tmp_path, monkeypatch):
        (tmp_path / "log-current.txt").write_text(json.dumps([{}]))
        monkeypatch.setattr("src.enrichment.path", tmp_path)

        with patch("src.enrichment.reverse_dns_search_dest_ips") as mock_rdns, \
             patch("shutil.copy"):
            mock_rdns.return_value = ([], [])
            enrich_logs()

        mock_rdns.assert_called_once_with("log-current.txt")

    def test_enrich_logs_copies_enriched_file_as_timestamped_backup(self, tmp_path, monkeypatch):
        (tmp_path / "log-current.txt").write_text(json.dumps([{}]))
        monkeypatch.setattr("src.enrichment.path", tmp_path)

        with patch("src.enrichment.reverse_dns_search_dest_ips") as mock_rdns, \
             patch("shutil.copy") as mock_copy:
            mock_rdns.return_value = ([], [])
            enrich_logs()

        mock_copy.assert_called_once()
        src_path = str(mock_copy.call_args[0][0])
        dst_path = str(mock_copy.call_args[0][1])
        assert "log-enriched-current.txt" in src_path
        assert "log-enriched-" in dst_path
