import json
import requests
import logging

def verify_ip():
    # Configure logging
    logging.basicConfig(filename='verify_ip.log',
                        level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s'
                        )

    # General configuration
    api_key = 'a4f2a258ed0cf5856b812d5f9d54f5477b4e300844f3b25cf2894f46858df3c6e0dcf757625300d8'
    ip_address = input('Ingrese la IP que desea verificar: ')
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'

    # IP query through the AbuseIPDB API
    headers = {
        'Accept': 'application/json',
        'key': api_key
    }

    # Error management
    try:
        response = requests.get(url, headers=headers)
        # Error management
        if response.status_code == 200:
            data = response.json()
            abuse_confidence = data["data"]["abuseConfidenceScore"]

            # Verifies how reliable the IP address is according to its confidence of abuse
            # "Confidence in abuse" refers to how likely the IP is to be malicious
            if abuse_confidence > 50:
                message = f'\nLa dirección IP {ip_address} no es confiable\nTiene un porcentaje de abuso de: {abuse_confidence}%'
                print(message)
                logging.warning(message)
            else:
                message = f'\nLa dirección IP {ip_address} es confiable\nTiene un porcentaje de abuso de: {abuse_confidence}%'
                print(message)
                logging.info(message)

            info = f'\nInformación general de la IP:\n{json.dumps(data, indent=4)}'
            logging.info(f'Información de la IP {ip_address} conseguida con éxito')
            return info

        else:
            error_message = f'Error al conectar con la API {response.status_code}'
            print(error_message)
            logging.error(error_message)

    except requests.exceptions.HTTPError as http_err:
        error = f'Error HTTP: {http_err}'
        print(error)
        logging.error(error)
    except requests.exceptions.RequestException as err:
        error = f'Error en la solicitud: {err}'
        print(error)
        logging.error(error)

def main():
    """Main function to execute the IP verification."""
    return verify_ip()
