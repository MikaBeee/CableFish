import requests
import json
import os

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
        api_key = input("Zet hier je AbuseIPDB sleutel: ")
        with open(config_file, "w") as file:
            file.write(api_key)  # Sla de sleutel op in het bestand
        return api_key

# Gebruik de functie om je API-sleutel te verkrijgen
MYAPIKEY = get_api_key()

def load_checked_ips():
    """
    Laad de gecontroleerde IP's en hun data vanuit een bestand.
    """
    # Gebruik os.path.expanduser om de ~ te vervangen door het pad van de gebruikersmap
    file_path = os.path.expanduser(r"~\CableFish\Checked ips\checked_ips.json")
    
    # Controleer of het bestand bestaat
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return json.load(file)
    return {}

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
    # Controleer eerst of we de gegevens al hebben
    if ip in checked_ips:
        return checked_ips[ip]
    
    # Als het IP nog niet gecontroleerd is, maak een API-aanroep
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
        response.raise_for_status()  # Zorg ervoor dat de aanvraag succesvol was
        data = response.json()
        
        # Markeer het IP als gecontroleerd
        if data.get('data') and data['data'].get('isPublic'):
            abuse_confidence_score = data['data'].get('abuseConfidenceScore', 0)
            is_suspicious = abuse_confidence_score > 80  # Verdacht als de score > 80
            
            # Sla het IP en de status op
            checked_ips[ip] = {
                'is_suspicious': is_suspicious, 
                'location': data['data'].get('countryCode', 'Unknown'), 
                'domain': data['data'].get('domain', 'Unknown')
            }
            save_checked_ips(checked_ips)  # Sla de gegevens op in een bestand
            return checked_ips[ip]  # Geef de gegevens terug
        else:
            # Als geen gegevens beschikbaar zijn
            checked_ips[ip] = {'is_suspicious': False, 'location': 'Unknown', 'domain': 'Unknown'}
            save_checked_ips(checked_ips)
            return checked_ips[ip]  # IP is niet verdacht
    except requests.exceptions.RequestException as e:
        print(f"Fout bij het controleren van IP {ip}: {e}")
        return {'is_suspicious': False, 'location': 'Unknown', 'domain': 'Unknown'}