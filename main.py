import json

from src.collector import get_connections
from src.encryption import encrypt_data, load_key
from src.enrichment import enrich, enrich_dns
from tqdm import tqdm

# TODO: from src.risk_scorer import score_risk
# TODO: from src.summary import generate_summary


def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def main():
    # --- encryption initialization ---
    # If this fails, we skip writing the encrypted log file.
    encryption_ok = True
    try:
        load_key()
    except Exception as e:
        encryption_ok = False
        print(
            "ERROR: Could not initialize log encryption. "
            "Skipping log file output.\n"
            f"Details: {e}\n"
        )

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

    # --- encrypted log output ---
    # Turn results into JSON, encrypt them, and save only the encrypted file.
    if encryption_ok:
        try:
            results_json = json.dumps(results, indent=2).encode("utf-8")
            encrypted = encrypt_data(results_json)
            # NOTE: This will overwrite logs.enc every time.
            # We can change this later if we want to store past logs.
            with open("logs.enc", "wb") as f:
                f.write(encrypted)
            print("\nEncrypted logs saved to logs.enc")
        except Exception as e:
            print(
                "\nERROR: Could not encrypt/save logs. Skipping log write.\n"
                f"Details: {e}"
            )

    # TODO: write report.html in the next sprint


if __name__ == "__main__":
    main()
