import csv
from tkinter import filedialog


# Functie om de inhoud van de Treeview op te slaan naar een CSV-bestand
def save_treeview(tree, columns):
    # Open een dialoogvenster om een bestand op te slaan
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if file_path:
        with open(file_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            # Schrijf de kolomnamen (headers)
            writer.writerow(columns)
            # Schrijf de gegevens van de tree (rijen)
            for row in tree.get_children():
                writer.writerow(tree.item(row)["values"])

# Functie om de inhoud van een CSV-bestand in de Treeview in te laden
def load_treeview(tree, columns):

    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if file_path:
        # Verwijder alle bestaande items in de treeview
        tree.delete(*tree.get_children())
        with open(file_path, mode="r") as file:
            reader = csv.reader(file)
            next(reader)  # Skip de header row
            # Voeg de gegevens uit het bestand toe aan de Treeview
            for row in reader:
                tree.insert("", "end", values=row)

