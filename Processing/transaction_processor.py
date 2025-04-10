class TransactionProcessor:
    def __init__(self, file_path):
        self.history = {}
        self.transaction_counts = {}
        self.tree_items = {}
        self.file_path = file_path

    def process_log_entry(self, log_entry, update_callback):
        key = (log_entry["source_ip"], log_entry["dest_ip"])
    
        # Voeg entry toe aan history, of update als hij al bestaat
        if key in self.history:
            _, count = self.history[key]
            count += 1
        else:
            count = 1

        self.history[key] = (log_entry, count)
    
        # Geef de entry door voor verwerking in de GUI
        item_id = self.tree_items.get(key)  # Haal item_id op uit de mapping
        update_callback(item_id, log_entry, count)