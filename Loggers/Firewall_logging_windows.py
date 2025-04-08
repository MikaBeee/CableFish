# This file should only be run in a Windows environment
import time

log_file = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" #Reads the firewall log file

def tail_log(file_path):
    with open(file_path, "r") as file:  
        # Seek to the end of the file
        file.seek(0, 2) 

        while True:
            line = file.readline()
            if line:
                newest = line.strip()  # Process the new log line
            else:
                time.sleep(0.1)  # Wait before checking for new lines

tail_log(log_file)
