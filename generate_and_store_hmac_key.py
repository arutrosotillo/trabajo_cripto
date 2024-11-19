from cryptography.fernet import Fernet
import os

# Nombre del archivo donde se almacenará la clave
KEY_FILE = 'key.key'

def generate_and_store_key():
    """Generar una clave secreta y guardarla en un archivo."""

    # Generar una nueva clave
    key = Fernet.generate_key()

    # Guardar la clave en un archivo
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    print(f"Clave secreta generada y almacenada en {KEY_FILE}")

def load_key():
    """Cargar la clave desde el archivo."""
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError(f"El archivo {KEY_FILE} no existe. Genera la clave primero.")

    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key

if __name__ == '__main__':
    generate_and_store_key()
