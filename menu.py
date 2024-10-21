import ransomware_file_analyzer
import metadata_extraction
import shodan_search
import verify_ip
import vulnerability_headers

def show_menu():
    print("\n--- Menú de Módulos ---")
    print("1. Análisis de Ransomware")
    print("2. Extracción de Metadatos de Imágenes")
    print("3. Busqueda en servidores HTTP (Shodan)")  
    print("4. Verificacion de IP con IP Abuse Database")
    print("5. Escaneo de Vulnerabilidades en Headers HTTP")
    print("6. Salir")

def main():
    while True:
        show_menu()
        try:
            choice = int(input("Selecciona una opción (1-6): "))
            if choice == 1:
                directory = input("Introduce la ruta del directorio a analizar: ")
                if not ransomware_file_analyzer.validate_directory(directory):
                    print(f"Error: El directorio '{directory}' no es válido o no existe.")
                    continue
                ransomware_file_analyzer.detect_ransomware_activity(directory)
            elif choice == 2:
                image_path = input("Ingresa la ruta de la imagen (con extension .jpg): ")
                metadata_extraction.main(image_path)  # Llamada al módulo de extracción de metadatos
            elif choice == 3:
                query = input("Ingrese un servidor HTTP ('apache', 'nginx', 'mysql', 'cisco', 'IIS'): ")
                if query in ['apache', 'nginx', 'mysql', 'cisco', 'IIS']:
                    shodan_search.main(query)  # Llamada al módulo de búsqueda en Shodan
                else:
                    print("Por favor, ingrese uno de los valores indicados.")
            elif choice == 4:
                verify_ip.main()  # Llamada al módulo de verificación de IP
            elif choice == 5:
                vulnerability_headers.vulnerability_headers()  # Llamada al módulo de verificación de encabezados
            elif choice == 6:
                print("Saliendo del programa.")
                break
            else:
                print("Opción no válida. Por favor, selecciona un número entre 1 y 4.")
        except ValueError:
            print("Entrada no válida. Por favor, introduce un número.")

if __name__ == "__main__":
    main()
