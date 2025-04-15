import Apis.Abuseipdb as abuseipdb


class TransactionProcessor:
    def __init__(self, file_path):
        self.history = {}
        self.transaction_counts = {}
        self.tree_items = {}
        self.file_path = file_path
        self.checked_ips = abuseipdb.load_checked_ips()  # Laad de gecontroleerde IP's bij het opstarten
        self.paused = False 

    def process_log_entry(self, log_entry, update_callback):
        if self.paused:
            return
        else:
            key = (log_entry["source_ip"], log_entry["dest_ip"])
            # Verkrijg de checked_data voor het dest_ip (via de API-aanroep)
            checked_data = abuseipdb.get_ip_info(log_entry['dest_ip'])
        
            # Verkrijg de domain, location, en suspicious status van de API-aanroep
            domain = checked_data.get('domain', 'Unknown')
            location = checked_data.get('location', 'Unknown')
            is_suspicious = checked_data.get('is_suspicious', False)

            # Voeg entry toe aan history, of update als hij al bestaat
            if key in self.history:
                _, count, is_suspicious, location, domain = self.history[key]
                count += 1
            else:
                count = 1

            self.history[key] = (log_entry, count, is_suspicious, location, domain)
        

        
            # Geef de entry door voor verwerking in de GUI
            item_id = self.tree_items.get(key)  # Haal item_id op uit de mapping
            update_callback(item_id, log_entry, count, is_suspicious, location, domain)


