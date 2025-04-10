# This file should only be run in a Windows environment
import time
import tkinter

file_path = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
 #Reads the firewall log file
class PfirewallFileLogger:

    def __init__(self, file_path):
        self.file_path = file_path
        self.logs = [] 

    def read_log(self):
        with open(self.file_path, "r") as file:
            lines = file.readlines()
            return lines[-10:]  # Return the last 10 lines for example

    def display_log(self):
        log_lines = self.read_log()
        for line in log_lines:
            print(line.strip())  # Print each line without extra whitespace
    
    def parse_log_line(self, line):
        parts = line.strip().split()  # Simpele split
        if len(parts) < 10:  # if returned line shorter than 10 ignore and return None
            return None
        
        # Maak dictionary van de loglijn (afhankelijk van jouw logformaat!)
        return {
            "date": parts[0],
            "time": parts[1],
            "action": parts[2],
            "protocol": parts[3],
            "source_ip": parts[4],
            "dest_ip": parts[5],
            "source_port": parts[6],
            "dest_port": parts[7],
            "size": parts[8],
            "flags": parts[9]
        }


    def tail_log(self, update_callback):
        with open(self.file_path, "r") as file:
            file.seek(0, 2)  # Ga naar het einde

            while True:
                line = file.readline()
                if line:
                    parsed = self.parse_log_line(line)
                    if parsed:
                        self.logs.append(parsed)  # Voeg toe aan dictionary
                        update_callback(parsed)  # Stuur naar main.py
                else:
                    time.sleep(0.1)