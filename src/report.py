from datetime import datetime
from pathlib import Path
from typing import Optional


RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
RISK_RANK = {label: i for i, label in enumerate(RISK_ORDER)}


def _normalize_label(label: Optional[str]) -> str:
    """Return a clean risk label, defaulting to UNKNOWN."""
    label = (label or "UNKNOWN").upper()
    return label if label in RISK_RANK else "UNKNOWN"


def _risk_sort_key(result: dict) -> int:
    """Sort key so CRITICAL comes before HIGH, etc."""
    return RISK_RANK[_normalize_label(result.get("label"))]


def _issue_list(result: dict) -> list[str]:
    """Build a simple list of issue names based on warning flags."""
    issues: list[str] = []
    if result.get("port_suspicious"):
        issues.append("Suspicious Port")
    if result.get("port_mismatch"):
        issues.append("Port Mismatch")
    # "System Idle Process" is a normal Windows process and can show up without
    # a matching entry in our known-process list, so we don't flag it as unknown.
    process_name = (result.get("process_name") or "").strip()
    if not result.get("process_known") and process_name != "System Idle Process":
        issues.append("Unknown Process")
    return issues


def generate_report(results: list[dict], output_dir: str = "reports") -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    filename = output_path / f"report-{timestamp}.md"

    # Filter out local-only connections and connections with no remote address.
    # IMPORTANT: We create a new list and do NOT modify the original `results`.
    filtered_results = []
    for r in results:
        remote_ip = r.get("remote_ip")
        if remote_ip in (None, "", "127.0.0.1", "::1"):
            continue
        filtered_results.append(r)

    # Remove duplicate connections to reduce repeated rows.
    # Dedup is done AFTER filtering, and keeps the first occurrence only.
    report_results = []
    seen = set()
    for r in filtered_results:
        key = (r.get("process_name"), r.get("remote_ip"), r.get("remote_port"))
        if key in seen:
            continue
        seen.add(key)
        report_results.append(r)

    # Sort once so tables show a consistent risk order.
    sorted_results = sorted(report_results, key=_risk_sort_key)

    high_risk = [
        r
        for r in sorted_results
        if _normalize_label(r.get("label")) in ("HIGH", "CRITICAL")
    ]

    # Count issue types (based on warning flags).
    issue_counts = {"Suspicious Port": 0, "Port Mismatch": 0, "Unknown Process": 0}
    for r in report_results:
        for issue in _issue_list(r):
            issue_counts[issue] += 1

    # Count risk labels (missing labels become UNKNOWN).
    risk_counts = {label: 0 for label in RISK_ORDER}
    for r in report_results:
        risk_counts[_normalize_label(r.get("label"))] += 1

    has_warning_flags = any(count > 0 for count in issue_counts.values())
    has_issues = bool(high_risk) or has_warning_flags

    most_common_issues = [
        (name, count)
        for name, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)
        if count > 0
    ]

    lines = [
        "# Network Scan Report",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "## Summary",
        "",
        # Total connections reflects ALL activity, even if we hide noisy rows below.
        f"- Total connections: {len(results)}",
        f"- High/Critical connections: {len(high_risk)}",
    ]

    if len(high_risk) == 0:
        lines.append("- No major security risks were detected.")

    if most_common_issues:
        top = most_common_issues[:3]
        common_text = ", ".join(f"{name} ({count})" for name, count in top)
        lines.append(f"- Most common issue types: {common_text}")
    else:
        lines.append("- No major issues were found.")

    lines += [
        "",
        "Note: Local-only connections (127.0.0.1 / ::1) and connections without a remote address are excluded from this report for clarity.",
    ]

    lines += [
        "",
        "## Risk Breakdown",
        "",
        "| Risk | Count |",
        "|------|-------|",
    ]
    for label in RISK_ORDER:
        lines.append(f"| {label} | {risk_counts[label]} |")

    # Only show recommended actions if there are real issues to look at.
    if has_issues:
        lines += ["", "## Recommended Actions", ""]
        actions: list[str] = []
        if high_risk:
            actions.append("Review High and Critical connections first.")
        if issue_counts["Unknown Process"] > 0:
            actions.append("Check unknown processes and confirm they are expected.")
        if issue_counts["Suspicious Port"] > 0:
            actions.append("Investigate suspicious ports for unexpected services.")
        if issue_counts["Port Mismatch"] > 0:
            actions.append("Verify port mismatches (service name vs port).")
        lines += [f"- {action}" for action in actions]

    lines += ["", "---", ""]

    if high_risk:
        lines += ["## High / Critical Connections", ""]
        lines += _connection_table(high_risk)
        lines += [""]

    lines += ["## All Connections", ""]
    lines += _connection_table(sorted_results)

    filename.write_text("\n".join(lines), encoding="utf-8")
    return str(filename)


def _connection_table(connections: list[dict]) -> list[str]:
    header = "| Risk | Process | Remote | Port | Service | Owner | Flags |"
    sep    = "|------|---------|--------|------|---------|-------|-------|"
    rows = []
    for r in connections:
        label = _normalize_label(r.get("label"))
        issues = _issue_list(r)
        flags = ", ".join(issues) if issues else "-"
        rows.append(
            f"| {label:>8} "
            f"| {r.get('process_name','?')} "
            f"| {r.get('remote_ip','?')} "
            f"| {r.get('remote_port','?')} "
            f"| {r.get('service_name','?')} "
            f"| {r.get('dns_owner') or 'unknown'} "
            f"| {flags} |"
        )
    return [header, sep] + rows
