"""
test_risk_scorer.py
Unit tests for risk_scorer.py
Tests the score_risk function and the _is_trusted_path helper.
"""

from src.risk_scorer import score_risk, _is_trusted_path


# helper to build a fake connection dict so the tests stay readable
def make_conn(**overrides):
    base = {
        "process_name": "chrome.exe",
        "process_path": r"C:\Program Files\Google\Chrome\chrome.exe",
        "process_known": True,
        "remote_ip": "142.250.80.46",
        "remote_port": 443,
        "port_suspicious": False,
        "port_mismatch": False,
        "service_name": "HTTPS",
    }
    base.update(overrides)
    return base


# loopback connections should always come back LOW with a score of 0
# even if every other indicator is set
def test_loopback_returns_low():
    conn = make_conn(remote_ip="127.0.0.1")
    result = score_risk(conn)
    assert result["score"] == 0
    assert result["label"] == "LOW"

    # ipv6 loopback too
    conn2 = make_conn(remote_ip="::1")
    assert score_risk(conn2)["label"] == "LOW"

    # loopback should override even the worst flags
    conn3 = make_conn(
        remote_ip="127.0.0.1",
        process_name="powershell.exe",
        process_path="unknown",
        process_known=False,
        port_suspicious=True,
        port_mismatch=True,
    )
    assert score_risk(conn3)["score"] == 0


# powershell, certutil etc. making outbound connections should get flagged as LOLBins.
# also makes sure a process with "powershell" in the name but isn't actually powershell
# doesn't get falsely flagged
def test_lolbin_detection():
    # powershell making an outbound connection, +20 unknown, +30 lolbin
    conn = make_conn(process_name="powershell.exe", process_known=False)
    result = score_risk(conn)
    assert result["score"] >= 50
    assert any("LOLBin" in r for r in result["reasons"])

    # certutil should also be flagged
    conn2 = make_conn(process_name="certutil.exe", process_known=False)
    assert any("certutil.exe" in r for r in score_risk(conn2)["reasons"])

    # something like my_powershell_wrapper.exe shouldn't be flagged as a LOLBin
    # since it just contains "powershell" in the name
    conn3 = make_conn(process_name="my_powershell_wrapper.exe", process_known=False)
    assert not any("LOLBin" in r for r in score_risk(conn3)["reasons"])

    # normal chrome.exe should be LOW
    assert score_risk(make_conn())["label"] == "LOW"


# system processes like svchost.exe running from outside system32 are suspicious
def test_spoofed_system_process():
    # svchost from temp folder, classic malware trick
    conn = make_conn(
        process_name="svchost.exe",
        process_path=r"C:\Users\victim\AppData\Local\Temp\svchost.exe",
    )
    result = score_risk(conn)
    assert any("masquerading" in r.lower() for r in result["reasons"])
    assert result["score"] >= 35

    # but svchost from the actual system32 should be fine
    conn2 = make_conn(
        process_name="svchost.exe",
        process_path=r"C:\Windows\System32\svchost.exe",
    )
    assert not any("masquerading" in r.lower() for r in score_risk(conn2)["reasons"])

    #every red flag should still cap the score at 100
    conn3 = make_conn(
        process_name="svchost.exe",
        process_path=r"C:\Users\victim\Temp\svchost.exe",
        process_known=False,
        port_suspicious=True,
        port_mismatch=True,
    )
    result3 = score_risk(conn3)
    assert result3["score"] <= 100
    assert result3["label"] == "CRITICAL"


# tests the _is_trusted_path helper directly
def test_is_trusted_path():
    # standard windows locations should be trusted
    assert _is_trusted_path(r"C:\Windows\System32\svchost.exe") is True
    assert _is_trusted_path(r"C:\Program Files\Google\Chrome\chrome.exe") is True
    assert _is_trusted_path(r"C:\Program Files (x86)\Microsoft\edge.exe") is True

    # user temp folders shouldn't be trusted
    assert _is_trusted_path(r"C:\Users\victim\AppData\Local\Temp\evil.exe") is False

    # bad inputs should fail safely
    assert _is_trusted_path("") is False
    assert _is_trusted_path(None) is False
    assert _is_trusted_path("unknown") is False  # collector uses this when it cant resolve

    # case shouldn't matter on windows
    assert _is_trusted_path(r"C:\WINDOWS\SYSTEM32\svchost.exe") is True

    # forward slashes should also work
    assert _is_trusted_path("C:/Windows/System32/svchost.exe") is True