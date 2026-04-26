# Unit tests for Jai Pope

import pytest
from src.enrichment import display_process_path
# the following tests are for the display_process_path function within enrichment.py. The purpose of this function is to grab and display the process path of a connection
# Test cases cover complete connection dictionary, as well as abnormal cases such as unknown paths, empty dicts, and special characters in paths
@pytest.mark.parametrize("connection, expected_strings", [
    # Test 1: Complete connection dict
    (
        {"process_name": "explorer.exe", "process_path": "C:\\Windows\\explorer.exe", "pid": 1234},
        ["Process: explorer.exe", "(PID: 1234)", "Path: C:\\Windows\\explorer.exe", "Verified path"]
    ),
    # Test 2: Unknown process path
    (
        {"process_name": "malware.exe", "process_path": "unknown", "pid": 5678},
        ["Process: malware.exe", "Path: unknown", "Could not determine path"]
    ),
    # Test 3: Empty connection dict
    (
        {},
        ["Process: unknown", "(PID: ?)", "Path: unknown"]
    ),
    # Test 4: Special characters
    (
        {"process_name": "app with spaces.exe", "process_path": "C:\\Program Files (x86)\\App\\app with spaces.exe", "pid": 7777},
        ["app with spaces.exe", "Program Files (x86)", "Verified path"]
    )
])
def test_display_process_path(connection, expected_strings):
    """Test display_process_path with multiple scenarios."""
    result = display_process_path(connection)
    
    for expected in expected_strings:
        assert expected in result

