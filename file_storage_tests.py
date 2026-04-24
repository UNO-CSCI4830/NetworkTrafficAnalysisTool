import filecmp
import pytest
import os
import sys
import subprocess

#These were the unit tests written by Niko Luebbert for the Unit 3 Testing Team Project

netscan_results = os.path.expanduser('~/netscan_results')
unenriched_log = os.path.expanduser('~/netscan_results/log-current.txt')
enriched_log = os.path.expanduser('~/netscan_results/log-enriched-current.txt')

 # Returns True if files are identical, False otherwise.
def test_enriched_log_is_different_from_log():
    #Make sure that the enriched log isn't the same as the original log
    assert filecmp.cmp(unenriched_log, enriched_log, shallow=False) == False

#Makes sure lines like "enriched_dns_owner": "GOOGLE-CLOUD-PLATFORM - Google LLC, US" were added to the log.
def test_dns_data_was_added_to_enriched_log():
    #make sure that the enriched_dns_owner tag was added to the enriched log:
    dns_was_added = False
    with open(enriched_log, "r") as en_l:
        for line in en_l:
            if '"enriched_dns_owner":' in line:
                print(line)
                dns_was_added = True
                break

    assert dns_was_added == True


#make sure that a new log-current.txt and log-enriched-current.txt show up when you run main.py
#log files shouldn't disappear between runs.
def test_logs_arent_lost_beween_run_of_main():
    original_number_of_logs = len(os.listdir(netscan_results))
    
    #stdout=subprocess.DEVNULL is to prevent polluting the test logs with program output
    subprocess.run([sys.executable, "main.py"], stdout=subprocess.DEVNULL, check=True)

    new_number_of_logs = len(os.listdir(netscan_results))

    #log-enriched-current.txt will get copied to a place like log-enriched-2026-04-05_15-33-50.txt on each subsequent run. In most cases, there should be one new log and one new enriched log every time main.py is run.
    assert new_number_of_logs == (original_number_of_logs + 2)

#make sure that a new log-current.txt and log-enriched-current.txt show up even if you run collector.py and enrichment.py on their own outside of main.py
#log files shouldn't disappear between runs.
def test_logs_arent_lost_beween_standalone_utilities_run():
    original_number_of_logs = len(os.listdir(netscan_results))
    
    #stdout=subprocess.DEVNULL is to prevent polluting the test logs with program output
    subprocess.run([sys.executable, "src/collector.py"], stdout=subprocess.DEVNULL, check=True)
    subprocess.run([sys.executable, "src/enrichment.py"], stdout=subprocess.DEVNULL, check=True)

    new_number_of_logs = len(os.listdir(netscan_results))

    #log-enriched-current.txt will get copied to a place like log-enriched-2026-04-05_15-33-50.txt on each subsequent run, and vice versa for the unenriched logs. In most cases, there should be one new log and one new enriched log every time main.py is run.
    assert new_number_of_logs == (original_number_of_logs + 2)
