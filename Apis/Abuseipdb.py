import requests
import json
import os
from datetime import datetime, timedelta

# Laad de gecontroleerde IP's wanneer de applicatie start
config_file = "config.txt"

# Functie om de API-sleutel te verkrijgen
def get_api_key():
    # Kijk of het bestand bestaat
    if os.path.exists(config_file):
        with open(config_file, "r") as file:
            api_key = file.read().strip()  # Leest de sleutel uit het bestand
        return api_key
    else:
        # Als het bestand niet bestaat, vraag de sleutel en sla deze op
        api_key = input("Put your ABUSEIPDB key here: ")
        with open(config_file, "w") as file:
            file.write(api_key)  # Sla de sleutel op in het bestand
        return api_key

# Gebruik de functie om je API-sleutel te verkrijgen
MYAPIKEY = get_api_key()

def load_checked_ips():
    """
    Laad de gecontroleerde IP's en hun data vanuit een bestand.
    Verwijder IPs die ouder zijn dan 7 dagen.
    """
    file_path = os.path.expanduser(r"~\CableFish\Checked ips\checked_ips.json")
    if not os.path.exists(file_path):
        return {}

    with open(file_path, 'r') as file:
        data = json.load(file)

    # Filter oude data (>7 dagen)
    cleaned_data = {}
    for ip, info in data.items():
        last_checked_str = info.get("last_checked")
        if last_checked_str:
            try:
                last_checked = datetime.fromisoformat(last_checked_str)
                if datetime.now() - last_checked < timedelta(days=7):
                    cleaned_data[ip] = info
            except ValueError:
                pass  # Fout in datumformaat? Skip gewoon

    return cleaned_data

def save_checked_ips(checked_ips):
    """
    Sla de gecontroleerde IP's en hun data op in een bestand.
    """
    # Gebruik os.path.expanduser om de ~ te vervangen door het pad van de gebruikersmap
    file_path = os.path.expanduser(r"~\CableFish\Checked ips\checked_ips.json")
    
    # Maak de map als deze nog niet bestaat
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # Sla de data op in het bestand
    with open(file_path, 'w') as file:
        json.dump(checked_ips, file, indent=4)


# Laad de gecontroleerde IP's bij het starten van de applicatie
checked_ips = load_checked_ips()



def get_ip_info(ip):
    # Controleer of we het IP al eerder hebben gecontroleerd en of die controle minder dan 24 uur geleden was
    if ip in checked_ips:
        last_checked_str = checked_ips[ip].get('last_checked')
        if last_checked_str:
            last_checked = datetime.fromisoformat(last_checked_str)
            if datetime.now() - last_checked < timedelta(hours=24):
                return checked_ips[ip]  # Gebruik cached data

    # Als het IP nog niet gecontroleerd is of de laatste controle is ouder dan 24 uur
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': MYAPIKEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        if data.get('data') and data['data'].get('isPublic'):
            abuse_confidence_score = data['data'].get('abuseConfidenceScore', 0)
            is_suspicious = abuse_confidence_score > 80
            
            checked_ips[ip] = {
                'is_suspicious': is_suspicious,
                'location': data['data'].get('countryCode', 'Unknown'),
                'domain': data['data'].get('domain', 'Unknown'),
                'last_checked': datetime.now().isoformat()
            }
            save_checked_ips(checked_ips)
            return checked_ips[ip]
        else:
            checked_ips[ip] = {
                'is_suspicious': False,
                'location': 'Unknown',
                'domain': 'Unknown',
                'last_checked': datetime.now().isoformat()
            }
            save_checked_ips(checked_ips)
            return checked_ips[ip]

    except requests.exceptions.RequestException as e:
        print(f"Fout bij het controleren van IP {ip}: {e}")
        return {
            'is_suspicious': False,
            'location': 'Unknown',
            'domain': 'Unknown',
            'last_checked': datetime.now().isoformat()
        }
