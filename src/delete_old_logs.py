from pathlib import Path
from datetime import datetime
import os


def delete_old_logs():
    path = Path.home() / "netscan_results"
    
    print("INIT: deleting expired logs... (over 1 month old)")
    for f in Path(path).iterdir():
        if f.is_file():
            log_date = f.name #the file name
            log_date = log_date.replace("log-enriched-", "")
            log_date = log_date.replace("log-", "")
            log_date = log_date.split(".")
            #print(log_date[0]) #the first split element is before the file extension
            now = datetime.now()
            
            log_dt = datetime.now() #for debugging. remove me!
            #(the number of elapsed years * 12) + (elapsed months)

            elapsed_months = 0
            try:
                log_dt = datetime.strptime(log_date[0], "%Y-%m-%d_%H-%M-%S")
                elapsed_months = ((now.year - log_dt.year) * 12) + (now.month - log_dt.month)
                #if a log is at least a month old: delete it.
                if (elapsed_months > 0):
                    print("Date of expired log: " + str(log_dt))
                    print("Elapsed Months: " + str(elapsed_months))

                    #delete the file:
                    if f.exists():
                        print('deleting.')
                        os.remove(f)
                
            except:
                #print("file that isn't a validly named log: " + log_date[0]) #too annoying for non-debugging use.
                pass
               
     
            
          
    print("Done deleting expired logs.\n\n")

if __name__ == "__main__":
    delete_old_logs()
