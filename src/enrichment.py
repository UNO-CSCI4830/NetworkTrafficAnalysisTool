import os
from pathlib import Path
import json

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
    from ipwhois import IPWhois
    from pprint import pprint
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


if __name__ == "__main__":
    enrich_logs()
