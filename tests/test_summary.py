import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.summary import generate_connection_summary, summarize_data

def test_connection_summary():
    connection = {
        "process_name": "chrome.exe",
        "remote_ip": "142.250.190.14",
        "remote_port": 443,
        "label": "LOW",
        "score": 10
    }

    summary = generate_connection_summary(connection)

    assert "chrome.exe" in summary
    assert "142.250.190.14" in summary
    assert "443" in summary
    assert "LOW" in summary
    assert "10" in summary


def test_summarize_data():
    summary = summarize_data(500, 1500)

    assert "500" in summary
    assert "1500" in summary
    assert "2000" in summary