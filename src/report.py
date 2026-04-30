from datetime import datetime
from pathlib import Path


def generate_report(results: list[dict], output_dir: str = ".") -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = Path(output_dir) / f"report-{timestamp}.md"

    high_risk = [r for r in results if r.get("label") in ("HIGH", "CRITICAL")]

    lines = [
        f"# Network Scan Report",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Total connections:** {len(results)}  ",
        f"**High/Critical:** {len(high_risk)}  ",
        f"",
        f"---",
        f"",
    ]

    if high_risk:
        lines += ["## High / Critical Connections", ""]
        lines += _connection_table(high_risk)
        lines += [""]

    lines += ["## All Connections", ""]
    lines += _connection_table(results)

    filename.write_text("\n".join(lines), encoding="utf-8")
    return str(filename)


def _connection_table(connections: list[dict]) -> list[str]:
    header = "| Risk | Process | Remote | Port | Service | Owner | Flags |"
    sep    = "|------|---------|--------|------|---------|-------|-------|"
    rows = []
    for r in connections:
        flags = ""
        if r.get("port_suspicious"): flags += "⚠ suspicious port  "
        if r.get("port_mismatch"):   flags += "⚠ port mismatch  "
        if not r.get("process_known"): flags += "? unknown process"
        rows.append(
            f"| {r.get('label','?'):>8} "
            f"| {r.get('process_name','?')} "
            f"| {r.get('remote_ip','?')} "
            f"| {r.get('remote_port','?')} "
            f"| {r.get('service_name','?')} "
            f"| {r.get('dns_owner') or 'unknown'} "
            f"| {flags.strip() or '-'} |"
        )
    return [header, sep] + rows
