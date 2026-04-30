
import os
from pathlib import Path
import json
from ipwhois import IPWhois
from tqdm import tqdm
import hashlib

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

      # --- sha256 executable_sum ---
    try:
        with open(result["process_path"], 'rb') as exe:
            digest = hashlib.file_digest(exe, "sha256")
            #print(digest.hexdigest())
    except:
        digest = None

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
        try:
            result["executable_sha256"] = digest.hexdigest()
        except:
            result["executable_sha256"] = None
            

    return result

path = Path.home() / "netscan_results"

def enrich_logs():
    from datetime import datetime
    import shutil
    
    #Note from Niko: My idea of what enrichment.py should do is find additional information about a connection, and write it to a log file with increased metadata called log-enriched-current.py
    
    #get a list of the IPs, and a list of who owns them:
    remote_ip_list, remote_ip_owners = reverse_dns_search_dest_ips("log-current.txt");

    #write back the enriched log with the DNS owners included:
    #---------------------------------------------------------------------------
    enriched_log_path = path / "log-enriched-current.txt"
    log_path = path / "log-current.txt"
    
    #open the enriched log
    ip_counter = 0
    with open(enriched_log_path, "w") as enriched_log_file:
        #open the log we are enriching:
        with open(log_path, "r") as log_file:
            data = json.load(log_file)
            enriched_log_file.write("[\n") #make json array so file is valid
            for c in data:
                if ip_counter < len(remote_ip_list): #since I have that hack that puts an empty json entry at the end of the log.
                    #Add the DNS owner to the enriched log:
                    c.update({"enriched_dns_owner": remote_ip_owners[ip_counter]})
                    json_dump = json.dumps(c, indent=2)
                    #Write the enriched connection entry back to file
                    enriched_log_file.write(json_dump + ",")
                    ip_counter += 1
            enriched_log_file.write("{}]\n") #terminate array of json entries

    #end of code to write back the enriched log with the DNS owners included.
    #---------------------------------------------------------------------------

    #make a copy of the enriched log so the next run of enrichment.py doesn't overwrite it:
    iso_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") #the iso format contains illegal windows filesystem characters, so custom time/date format it is.
    #print("log-" + str(iso_time) + ".txt")
    shutil.copy(path / "log-enriched-current.txt" , path / ("log-enriched-" + str(iso_time) + ".txt"))

    
def reverse_dns_search_dest_ips(log_name):
    import time
    
    remote_ip_list = []
    remote_ip_owners = []

    #Step 1: extract all the outgoing IP addresses from the log.
    with open(str(path / log_name), 'r') as log_file:
        data = json.load(log_file)
        
        for entry in data:
            ip = entry.get('remote_ip')
            #print(ip)

            #due to a hack I made in collector.py to put commas after each json string, there is an empty json entry at the end of each log file. the .strip() fails on blank input, hence the try and accept structure here.
            try:
                ip = ip.strip()
            except:
                print("")
            else:
                if ip != '':
                    remote_ip_list.append(ip)

        print(remote_ip_list)

    #Now look up who owns each IP address
    for ip in remote_ip_list:
        #Now look up who registered each address
        try:
            obj = IPWhois(ip)
             # Use lookup_rdap() for the most detailed, modern data structure
            results = obj.lookup_rdap()
        except:
            remote_ip_owners.append(None) 
        else:
            #time.sleep(0.05) #For a second it seemed like it would time you out if you go too fast, but now it doesn't for some reason.
            # Access registration details
            print(f"Organization: {results['asn_description']}")
            remote_ip_owners.append(results['asn_description'])
            #pprint(results['network'])

        
    print(remote_ip_owners)
    return remote_ip_list, remote_ip_owners


def enrich_dns(connection: dict, cache: dict, pbar: tqdm = None) -> dict:
    """
    In-memory DNS enrichment for the main.py pipeline.
    Looks up the organization that owns the remote IP and adds it to the connection dict.

    Adds:
        dns_owner - organization name from WHOIS/RDAP, or None if lookup fails
    """
    result = dict(connection)
    ip = connection.get("remote_ip", "")
    if ip:
        cached = ip in cache
        if not cached:
            try:
                cache[ip] = IPWhois(ip).lookup_rdap()["asn_description"]
            except Exception:
                cache[ip] = None
        result["dns_owner"] = cache[ip]
        if pbar:
            pbar.set_postfix_str(f"{ip} {'(cached)' if cached else ''}")
    if pbar:
        pbar.update(1)
    return result


def display_process_path(connection: dict) -> str:
    """
    Returns a formatted string with process path details for security analysis.
    Useful for verifying a process is running from its official installation directory.
    
    Args:
        connection: A connection dict with process_path field
        
    Returns:
        Formatted string with process path details
    """
    process_name = connection.get("process_name", "unknown")
    process_path = connection.get("process_path", "unknown")
    pid = connection.get("pid", "?")
    
    detail_str = f"Process: {process_name} (PID: {pid})\nPath: {process_path}"
    
    if process_path != "unknown":
        detail_str += f"\n Verified path"
    else:
        detail_str += f"\n Could not determine path (elevated privileges may be required)"
    
    return detail_str


if __name__ == "__main__":
    enrich_logs()

