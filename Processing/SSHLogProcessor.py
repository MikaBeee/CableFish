import time
import re
import os
import json
import threading

class SSHLogProcessor:

    def __init__(self, log_file_path, ssh_config_path):
        self.log_file_path = log_file_path
        self.ssh_config_path = ssh_config_path
        self.logs = []

    def get_dest_ip_from_ssh_config(self):
        """
        Haal het IP-adres van de 'Host' uit het SSH-configuratiebestand (in JSON-formaat).
        :param ssh_config_path: Pad naar het SSH-configuratiebestand (JSON).
        :return: IP-adres of None als het niet wordt gevonden.
        """
        if not os.path.exists(self.ssh_config_path):
            print(f"SSH-configuratiebestand niet gevonden: {self.ssh_config_path}")
            return None

        with open(self.ssh_config_path, 'r') as f:
            try:
                config = json.load(f)
                return config.get("host")
            except json.JSONDecodeError:
                print(f"Fout bij het ontleden van het JSON-bestand: {self.ssh_config_path}")
                return None

    def process_log_line(self, line):
        """
        Verwerkt een enkele logregel en retourneert een dict met source_ip, dest_ip, datum, tijd.
        :param line: De regel uit het logbestand.
        :return: Dictionary met source_ip, dest_ip, datum, tijd of None als niet geldig.
        """
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        match = pattern.findall(line)
        if match and len(match) >= 1:
            source_ip = match[0]  # Eerste IP in de regel is de source-ip
            dest_ip = self.get_dest_ip_from_ssh_config()  # Haal dest_ip uit het configuratiebestand

            if dest_ip:
                # Parse de datum en tijd van de logregel
                parts = line.strip().split(" ")
                if len(parts) >= 2:
                    date = parts[0]  # Datum
                    return {
                        "source_ip": dest_ip,
                        "dest_ip": source_ip,
                        "date": date
                    }
        return None

    def read_log(self):
        """
        Leest de laatste 10 regels van het SSH-logbestand.
        :return: Lijst van logregels.
        """
        with open(self.log_file_path, "r") as file:
            lines = file.readlines()
            return lines  # Return de laatste 10 regels als voorbeeld

    def display_log(self):
        """
        Toont de laatste 10 regels van het logbestand.
        """
        log_lines = self.read_log()
        for line in log_lines:
            parsed = self.process_log_line(line)
            if parsed:
                print(parsed)  # Print de verwerkte loglijn zonder extra witruimte

    def tail_log(self, update_callback):
        """
        Leest het logbestand in real-time en verwerkt nieuwe regels.
        :param update_callback: De callbackfunctie die wordt aangeroepen voor elke nieuwe logregel.
        """

        while self.log_file_path is None or not os.path.exists(self.log_file_path):
            time.sleep(1)  # Wacht tot het bestand beschikbaar is)
            


        with open(self.log_file_path, "r") as file:
             # Ga naar het einde van het bestand
            file.seek(0, 2)  
            while True:
                line = file.readline()
                if line:
                    parsed = self.process_log_line(line)
                    if parsed:
                        self.logs.append(parsed)  # Voeg toe aan de lijst
                        update_callback(parsed)  # Stuur naar de callback functie
                else:
                    time.sleep(10)

# Voorbeeld gebruik van de SSHLogProcessor:
log_file_path = r"Loggers/SshLogs/auth.log"  # Het pad naar je SSH logbestand
ssh_config_path = r"ssh_config.json"  # Het pad naar je SSH configuratiebestand

# Callbackfunctie die de verwerkte loglijn ontvangt
def update_ssh_log(parsed_log):
    if parsed_log:
        print(f"Source IP: {parsed_log['source_ip']}, Dest IP: {parsed_log['dest_ip']}, Date: {parsed_log['date']}, Time: {parsed_log['time']}")

# Start de logtail in een aparte thread (om het bestand real-time te volgen)

