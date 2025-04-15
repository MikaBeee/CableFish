import tkinter as tk
from tkinter import ttk
import threading
from Loggers import Pfirewall_logging_windows as pfirewall
from Loggers import UbuntuSSHlogger as sshlogger
from Processing import transaction_processor, SSHLogProcessor
import sv_ttk
from treeview_utils import save_treeview, load_treeview
import SolutionBuilder

# ==== initialize the logger ====
sol = SolutionBuilder.Solutionbuilder()
sol.buildSSHlogfiles()
sol.buildAPIConfigFile()


logging_paused = False

def pause_logging():
    global logging_paused
    logging_paused = True
    processor.paused = True
    print("Logging paused")

def resume_logging():
    global logging_paused
    logging_paused = False
    processor.paused = False
    if log_thread is None or not log_thread.is_alive():
        start_logger()
    print("Logging resumed")

# ==== Setup main window ====
root = tk.Tk()
root.title("Network Monitoring Suite")
root.geometry("1600x800")
sv_ttk.set_theme("dark")

# ==== Notebook (tabs) ====
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# ==== Create Frames for each Tab ====
pfirewall_frame = ttk.Frame(notebook)
live_network_frame = ttk.Frame(notebook)
ssh_frame = ttk.Frame(notebook)

notebook.add(pfirewall_frame, text='Pfirewall')
notebook.add(live_network_frame, text='Live Network')
notebook.add(ssh_frame, text='SSH')

# === SSH Tab content ====

# ==== Treeview setup ====
columnsssh = ("Date", "Source IP", "Dest IP", "Count", "Suspicious", "Location", "Domain")

tree_frame = ttk.Frame(ssh_frame)
tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

ssh_tree = ttk.Treeview(tree_frame, columns=columnsssh, show="headings")
for col in columnsssh:
    ssh_tree.heading(col, text=col)
    ssh_tree.column(col, width=80, anchor="center")
ssh_tree.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=ssh_tree.yview)
ssh_tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")

def process_new_ssh_entry(item_id, log_entry, count, is_suspicious, location, domain):
    if logging_paused:
        return

    # Extract necessary fields from the log_entry
    else:
        dest_ip = log_entry["dest_ip"]
        src_ip = log_entry["source_ip"]
        log_date = log_entry.get("date", "")  # Assuming the log has a 'date' field
        action = log_entry.get("action", "")  # Assuming 'action' field is part of SSH logs

        # Prepare values for the treeview columns
        values = (
            log_date,  # Date
            dest_ip,    # Destination IP
            src_ip,    # Source IP
            count,     # Count
            is_suspicious,  # Suspicious
            location,  # Location
            domain     # Domain
        )

        # Update or insert the SSH log entry into the treeview using the simplified update function
        item_id = update_ssh_treeview(item_id, values)

        # Assuming you still want to keep track of the tree item
        processor.tree_items[(src_ip, dest_ip)] = item_id


def update_ssh_treeview(item_id, values):
    """A simplified function to insert or update SSH entries in the ssh_treeview."""
    
    # If item_id is None or doesn't exist in the tree, insert a new entry
    if not item_id or not ssh_tree.exists(item_id):
        return ssh_tree.insert("", "end", values=values)
    
    # If item already exists, update the existing entry
    ssh_tree.item(item_id, values=values)
    return item_id

# === Buttons ===
def loadbuttonfunction(tree, columns):
    pause_logging()
    load_treeview(tree, columns)

button_frame = ttk.Frame(ssh_frame)
button_frame.pack(fill='x', padx=10, pady=5)

save_button = ttk.Button(button_frame, text="Save", command=lambda: save_treeview(ssh_tree, columns))
save_button.pack(side="right", padx=5)

load_button = ttk.Button(button_frame, text="Load", command=lambda: loadbuttonfunction(ssh_tree, columns))
load_button.pack(side="right", padx=5)

pause_button = ttk.Button(button_frame, text="Pause Logging", command=pause_logging)
pause_button.pack(side="left", padx=5)

resume_button = ttk.Button(button_frame, text="Resume Logging", command=resume_logging)
resume_button.pack(side="left", padx=5)

clearall_button = ttk.Button(button_frame, text="Clear All", command=lambda: ssh_tree.delete(*ssh_tree.get_children()))
clearall_button.pack(side="left", padx=5)
















# ==== Pfirewall Tab content ====

# ==== Filters ====
filter_frame = ttk.LabelFrame(pfirewall_frame, text="IP Filters")
filter_frame.pack(side="left", fill="x", padx=10, pady=5)

local_var = tk.BooleanVar(value=True)
internal_var = tk.BooleanVar(value=True)
public_var = tk.BooleanVar(value=True)

local_check = ttk.Checkbutton(filter_frame, text="(127.x.x.x)", variable=local_var, command=lambda: apply_filters())
internal_check = ttk.Checkbutton(filter_frame, text="(192.168.x.x) /  \n (10.x.x.x.)", variable=internal_var, command=lambda: apply_filters())
public_check = ttk.Checkbutton(filter_frame, text="Other", variable=public_var, command=lambda: apply_filters())

local_check.pack(side="top", anchor='w', padx=10, pady=5)
internal_check.pack(side="top", anchor='w', padx=10, pady=5)
public_check.pack(side="top", anchor='w', padx=10, pady=5)

# ==== Treeview setup ====
columns = ("Date", "Time", "Action", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port", "Size", "Count", "Suspicious", "Location", "Domain")

tree_frame = ttk.Frame(pfirewall_frame)
tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=80, anchor="center")
tree.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")

# === Buttons ===
def loadbuttonfunction(tree, columns):
    pause_logging()
    load_treeview(tree, columns)

button_frame = ttk.Frame(pfirewall_frame)
button_frame.pack(fill='x', padx=10, pady=5)

save_button = ttk.Button(button_frame, text="Save", command=lambda: save_treeview(tree, columns))
save_button.pack(side="right", padx=5)

load_button = ttk.Button(button_frame, text="Load", command=lambda: loadbuttonfunction(tree, columns))
load_button.pack(side="right", padx=5)

pause_button = ttk.Button(button_frame, text="Pause Logging", command=pause_logging)
pause_button.pack(side="left", padx=5)

resume_button = ttk.Button(button_frame, text="Resume Logging", command=resume_logging)
resume_button.pack(side="left", padx=5)

clearall_button = ttk.Button(button_frame, text="Clear All", command=lambda: tree.delete(*tree.get_children()))
clearall_button.pack(side="left", padx=5)

# ==== Helper functions ====

def is_local(ip):
    return ip.startswith("127.")

def is_internal(ip):
    return ip.startswith("192.168") or ip.startswith("10.")

def is_public(ip):
    return not is_local(ip) and not is_internal(ip)

def update_treeview(item_id, log_entry, count, is_suspicious, location, domain):
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
        count,
        is_suspicious,
        location,
        domain
    )

    if not item_id or not tree.exists(item_id):
        return tree.insert("", "end", values=values)
    else:
        tree.item(item_id, values=values)
        return item_id

def apply_filters():
    tree.delete(*tree.get_children())
    processor.tree_items.clear()

    for key, (log_entry, count, is_suspicious, location, domain) in processor.history.items():
        src_ip = log_entry['source_ip']

        if is_local(src_ip) and not local_var.get():
            continue
        if is_internal(src_ip) and not internal_var.get():
            continue
        if is_public(src_ip) and not public_var.get():
            continue

        item_id = update_treeview(None, log_entry, count, is_suspicious, location, domain)
        processor.tree_items[key] = item_id

# ==== Start logger thread ====

def start_logger():
    
    # starts the ssh log downloader

    global ssh_thread
    
    ssh_loggerdownloader = sshlogger.SSHLogger()
    ssh_thread = threading.Thread(target=ssh_loggerdownloader.start_monitoring)
    ssh_thread.daemon = True
    ssh_thread.start()

    # start the ssh log processor

    global ssh_log_thread
    ssh_processor = SSHLogProcessor.SSHLogProcessor(log_file_path, ssh_config_path)
    ssh_log_thread = threading.Thread(target=ssh_processor.tail_log, args=(lambda entry: processor.process_log_entry(entry, process_new_ssh_entry),))
    ssh_log_thread.daemon = True
    ssh_log_thread.start()

    # starts the pfirewall logger

    global log_thread
    logger = pfirewall.PfirewallFileLogger(file_path)
    log_thread = threading.Thread(target=logger.tail_log, args=(lambda entry: processor.process_log_entry(entry, process_new_entry),))
    log_thread.daemon = True
    log_thread.start()


    #ssh starter


def process_new_entry(item_id, log_entry, count, is_suspicious, location, domain):
    if logging_paused:
        return
    else:
        src_ip = log_entry["source_ip"]

        if is_local(src_ip) and not local_var.get():
            return
        if is_internal(src_ip) and not internal_var.get():
            return
        if is_public(src_ip) and not public_var.get():
            return
        if not item_id or not tree.exists(item_id):
            item_id = None

        new_item_id = update_treeview(item_id, log_entry, count, is_suspicious, location, domain)
        processor.tree_items[(log_entry["source_ip"], log_entry["dest_ip"])] = new_item_id

# ==== Start the app ====

file_path = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
log_file_path = r"Loggers/SshLogs/auth.log"
ssh_config_path = r"ssh_config.json"


processor = transaction_processor.TransactionProcessor(file_path)

threading.Thread(target=start_logger, daemon=True).start()

root.mainloop()
