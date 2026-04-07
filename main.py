import json

from src.collector import get_connections
from src.enrichment import enrich, enrich_dns
from tqdm import tqdm

# TODO: from src.risk_scorer import score_risk
# TODO: from src.summary import generate_summary


def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def main():
    # --- load reference data ---
    known_ports     = load_json("data/known_ports.json")
    known_processes = load_json("data/known_processes.json")

    # --- collect live connections ---
    connections = get_connections(kind="inet")
    print(f"Found {len(connections)} active connection(s).\n")

    # --- pipeline ---
    results = []
    dns_cache = {}
    with tqdm(total=len(connections), desc="DNS enrichment", unit="conn") as pbar:
        for conn in connections:
            # step 1: port + process enrichment
            conn = enrich(conn, known_ports, known_processes)

            # step 2: dns enrichment
            conn = enrich_dns(conn, dns_cache, pbar)

            # TODO: step 3: risk scoring
            # risk = score_risk(conn)
            # conn["score"]   = risk["score"]
            # conn["label"]   = risk["label"]
            # conn["reasons"] = risk["reasons"]

            # TODO: step 4: plain-English summary
            # conn["summary"] = generate_summary(conn)

            results.append(conn)

    # --- terminal output ---
    for r in results:
        print(
            f"[{r.get('label', 'unscored'):>8}] "
            f"{r['process_name']:<20} "
            f"{r['remote_ip']:>15}:{r.get('remote_port', '?')} "
            f"({r.get('service_name', 'unknown')}) "
            f"org={r.get('dns_owner', 'unknown')}"
            f"{' ⚠' if r.get('port_suspicious') else ''}"
            f"{' ?' if not r.get('process_known') else ''}"
        )

    # TODO: write report.html in the next sprint


if __name__ == "__main__":
    main()
