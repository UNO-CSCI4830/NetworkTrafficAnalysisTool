import json
import os

from src.encryption import load_key, encrypt_data
from src.collector import get_connections
from src.enrichment import enrich, enrich_dns, display_process_path
from src.delete_old_logs import delete_old_logs
from tqdm import tqdm
from pathlib import Path


from src.risk_scorer import score_risk
from src.data_transfer_tracker import create_tracker
# TODO: from src.summary import generate_summary


def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def main():
    ## --- create log folder if it doesn't exist ---
    log_path = Path.home() / "netscan_results"

    if (not log_path.is_dir()) and (log_path.exists()): #if there is a non-directory file in the way of netscan_results
        print("Error: Couldn't create log folder (~/netscan_results)")
        return -1
        
    if not log_path.exists(): #if the log directory doesn't exist (eg. first run of this program)
        #Otherwise, create the ~/netscan_results directory
        log_path.mkdir()
        print("creating " + str(log_path))
        os.system(f'attrib +h "{log_path}"')

    
    ## --- delete expired logs (over 1 month old)---
    delete_old_logs()
    
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

    # --- load reference data ---2
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

            # step 3: risk scoring
            risk = score_risk(conn)
            conn["score"]   = risk["score"]
            conn["label"]   = risk["label"]
            conn["reasons"] = risk["reasons"]

            # TODO: step 4: plain-English summary
            # conn["summary"] = generate_summary(conn)

            results.append(conn)

    # --- terminal output ---
    for r in results:
        #don't print a connection if it is only to localhost:
        if (r['remote_ip'] == ''):
            continue
        
        print(
            f"[{r.get('label', 'unscored'):>8}] "
            f"{r['process_name']:<20} "
            f"{r['remote_ip']:>15}:{r.get('remote_port', '?')} "
            f"({r.get('service_name', 'unknown')}) "
            f"org={r.get('dns_owner', 'unknown')}"
            f"{' ⚠' if r.get('port_suspicious') else ''}"
            f"{' ?' if not r.get('process_known') else ''}"
            f"{' sha256: ' + r.get('executable_sha256') if r.get('executable_sha256') else None}"
        )

    # --- (FR8) Per-Process Data Transfer Tracking ---
    try:
        tracker = create_tracker()
        process_transfer_stats = tracker.aggregate_by_connections(results)
        print(tracker.display_transfer_summary(process_transfer_stats, sort_by='total_bytes'))
        
        # Display top 10 processes by total bytes transferred
        top_processes = tracker.get_top_processes(process_transfer_stats, limit=10, sort_by='total_bytes')
        if top_processes:
            print("\nTOP 10 PROCESSES BY TOTAL DATA TRANSFER:")
            print("-" * 50)
            for idx, (process_name, data) in enumerate(top_processes, 1):
                print(f"{idx:2d}. {process_name:<30} {data['total_bytes']:>12,} bytes")
    except Exception as e:
        print(f"Warning: Could not generate data transfer summary: {e}\n")

    # --- (FR17)process path lookup (optional interactive feature) ---
    print("\n" + "="*80)
    print("PROCESS FILE PATH LOOKUP - Verify processes are running from official locations")
    print("="*80)
    while True:
        try:
            user_input = input("\nEnter process name or 'quit' to exit: ").strip()
            if user_input.lower() == 'quit':
                break
            
            matching = [r for r in results if user_input.lower() in r['process_name'].lower()]
            if matching:
                for match in matching:
                    print(f"\n{display_process_path(match)}")
            else:
                print(f"No processes found matching '{user_input}'")
        except KeyboardInterrupt:
            print("\nExiting...")
            break
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
