import tkinter as tk
from tkinter import ttk
import threading
from Loggers import Pfirewall_logging_windows as pfirewall
from Processing import transaction_processor
import sv_ttk

# ==== Setup main window ====
root = tk.Tk()
root.title("Firewall Log Viewer")
root.geometry("1000x600")
sv_ttk.set_theme("dark")

# ==== Filters ====
filter_frame = ttk.LabelFrame(root, text="IP Filters")
filter_frame.pack(fill="x", padx=10, pady=5)

local_var = tk.BooleanVar(value=True)
internal_var = tk.BooleanVar(value=True)
public_var = tk.BooleanVar(value=True)

local_check = ttk.Checkbutton(filter_frame, text="Local (127.x.x.x)", variable=local_var, command=lambda: apply_filters())
internal_check = ttk.Checkbutton(filter_frame, text="Internal (192.168.x.x)", variable=internal_var, command=lambda: apply_filters())
public_check = ttk.Checkbutton(filter_frame, text="Public", variable=public_var, command=lambda: apply_filters())

local_check.pack(side="left", padx=10, pady=5)
internal_check.pack(side="left", padx=10, pady=5)
public_check.pack(side="left", padx=10, pady=5)

# ==== Treeview setup ====
columns = ("Date", "Time", "Action", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port", "Size", "Flags", "Count")

tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=80, anchor="center")

tree.pack(fill="both", expand=True, padx=10, pady=5)

# ==== Scrollbar ====
scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")

# ==== Helper functions ====
# Veronderstelde functies voor het filteren van IP's
def is_local(ip):
    return ip.startswith("127.")

def is_internal(ip):
    return ip.startswith("192.") or ip.startswith("10.")  # Voeg je eigen ranges toe

def is_public(ip):
    # Controleer hier of het IP publiek is
    return not is_local(ip) and not is_internal(ip)

def update_treeview(item_id, log_entry, count):
    values = (
        log_entry["date"],
        log_entry["time"],
        log_entry["action"],
        log_entry["protocol"],
        log_entry["source_ip"],
        log_entry["dest_ip"],
        log_entry["source_port"],
        log_entry["dest_port"],
        log_entry["size"],
        log_entry["flags"],
        count
    )

    if not item_id or not tree.exists(item_id):
        # Voeg nieuw item toe
        return tree.insert("", "end", values=values)
    else:
        # Update bestaand item
        tree.item(item_id, values=values)
        return item_id


def apply_filters():
    tree.delete(*tree.get_children())  # Verwijder alle oude items uit de tree
    processor.tree_items.clear()  # Verwijder oude mappings van de processor

    # Loop door de geschiedenis en voeg alleen items toe die aan de filters voldoen
    for key, (log_entry, count) in processor.history.items():
        src_ip = log_entry['source_ip']

        # Filter op basis van lokale, interne, of publieke IP's
        if is_local(src_ip) and not local_var.get():
            continue
        if is_internal(src_ip) and not internal_var.get():
            continue
        if is_public(src_ip) and not public_var.get():
            continue

        # Update de treeview met de gefilterde data
        item_id = update_treeview(None, log_entry, count)
        processor.tree_items[key] = item_id  # Voeg het nieuwe item toe aan de mapping
# ==== Start logger thread ====

def start_logger():
    logger = pfirewall.PfirewallFileLogger(file_path)
    logger.tail_log(lambda entry: processor.process_log_entry(entry, process_new_entry))

def process_new_entry(item_id, log_entry, count):
    src_ip = log_entry["source_ip"]

    if is_local(src_ip) and not local_var.get():
        return
    if is_internal(src_ip) and not internal_var.get():
        return
    if is_public(src_ip) and not public_var.get():
        return
    if not item_id or not tree.exists(item_id):
        item_id = None

    # Voer de update uit van het item of voeg het toe als het nieuw is
    new_item_id = update_treeview(item_id, log_entry, count)
    processor.tree_items[(log_entry["source_ip"], log_entry["dest_ip"])] = new_item_id

# ==== Start the app ====

file_path = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
processor = transaction_processor.TransactionProcessor(file_path)

threading.Thread(target=start_logger, daemon=True).start()

root.mainloop()