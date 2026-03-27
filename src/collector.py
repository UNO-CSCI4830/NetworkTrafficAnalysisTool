"""
collector.py

Collects active network connections using psutil and normalizes each one
into a structured dict with the following fields:

    pid          - process ID (int or None)
    process_name - human-readable process name (str or "unknown")
    local_ip     - local-side IP address (str)
    local_port   - local-side port number (int)
    remote_ip    - remote-side IP address (str or "" if not connected)
    remote_port  - remote-side port number (int or None)
    protocol     - "tcp", "tcp6", "udp", "udp6", or "other" (str)
    status       - TCP state string e.g. "ESTABLISHED", "LISTEN", or "" for UDP (str)

Based on the official psutil netstat.py example:
  https://github.com/giampaolo/psutil/blob/master/scripts/netstat.py
"""

import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

import psutil

AF_INET6 = getattr(socket, "AF_INET6", object())

# Maps (address family, socket type) -> protocol label
_PROTO_MAP = {
    (AF_INET,  SOCK_STREAM): "tcp",
    (AF_INET6, SOCK_STREAM): "tcp6",
    (AF_INET,  SOCK_DGRAM):  "udp",
    (AF_INET6, SOCK_DGRAM):  "udp6",
}


def get_connections(kind: str = "inet") -> list[dict]:
    pid_to_name: dict[int, str] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid_to_name[proc.info["pid"]] = proc.info["name"] or "unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    connections: list[dict] = []

    for conn in psutil.net_connections(kind=kind):
        # --- protocol ---
        protocol = _PROTO_MAP.get((conn.family, conn.type), "other")

        # --- local address ---
        local_ip   = conn.laddr.ip   if conn.laddr else ""
        local_port = conn.laddr.port if conn.laddr else None

        # --- remote address ---
        remote_ip   = conn.raddr.ip   if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else None

        # --- status ---
        status = conn.status if conn.status not in (None, psutil.CONN_NONE) else ""

        # --- process info ---
        pid          = conn.pid
        process_name = pid_to_name.get(pid, "unknown") if pid is not None else "unknown"

        connections.append(
            {
                "pid":          pid,
                "process_name": process_name,
                "local_ip":     local_ip,
                "local_port":   local_port,
                "remote_ip":    remote_ip,
                "remote_port":  remote_port,
                "protocol":     protocol,
                "status":       status,
            }
        )

    return connections

if __name__ == "__main__":
    import json

    conns = get_connections(kind="inet")
    print(f"Found {len(conns)} active connection(s).\n")
    for c in conns:
        print(json.dumps(c, indent=2))
