def enrich(connection: dict, known_ports: dict, known_processes: dict) -> dict:
    """
    Enrich a connection dict with port and process metadata.

    Adds the following fields:
        service_name         - human-readable name for the remote port
        port_suspicious      - True if the port is flagged in known_ports
        process_known        - True if the process is in the whitelist
        process_description  - description of the process, or None if unknown
        port_mismatch        - True if a known process is using an unexpected port
    """
    result = dict(connection)

    remote_port = connection.get("remote_port")
    process_name = connection.get("process_name", "unknown")

    # --- port enrichment ---
    port_key = str(remote_port) if remote_port is not None else None
    port_info = known_ports.get(port_key, {})
    result["service_name"]    = port_info.get("service", "Unknown")
    result["port_suspicious"] = port_info.get("suspicious", False)

    # --- process enrichment ---
    proc_info = known_processes.get(process_name)
    if proc_info:
        result["process_known"]       = True
        result["process_description"] = proc_info["description"]
        expected_ports                = proc_info.get("expected_ports", [])
        result["port_mismatch"]       = (
            remote_port is not None and remote_port not in expected_ports
        )
    else:
        result["process_known"]       = False
        result["process_description"] = None
        result["port_mismatch"]       = False

    return result
