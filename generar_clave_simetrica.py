from cryptography.fernet import Fernet

# Generar una clave y guardarla en un archivo
key = Fernet.generate_key()

with open('key.key', 'wb') as key_file:
    key_file.write(key)
