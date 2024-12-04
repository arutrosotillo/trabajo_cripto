from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

# Función para generar una clave privada
def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Función para generar un certificado autofirmado
def generate_self_signed_cert(private_key, subject_name, organization_name):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Los Angeles"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    return cert

# Función para generar un certificado firmado por una CA
def generate_signed_cert(ca_cert, ca_key, csr):
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    return cert

# Inicializar Spotify (AC1) y JRE Productions (AC2)
def initialize_pki():
    # Generar AC raíz (Spotify)
    spotify_key = generate_private_key()
    spotify_cert = generate_self_signed_cert(spotify_key, u"Spotify", u"Spotify")

    # Guardar clave privada y certificado de Spotify
    with open("spotify_key.pem", "wb") as f:
        f.write(spotify_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("spotify_cert.pem", "wb") as f:
        f.write(spotify_cert.public_bytes(serialization.Encoding.PEM))

    # Generar AC subordinada (JRE Productions)
    jre_key = generate_private_key()
    jre_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Los Angeles"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"JRE Productions"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"JRE Productions"),
    ])).sign(jre_key, hashes.SHA256())

    jre_cert = generate_signed_cert(spotify_cert, spotify_key, jre_csr)

    # Guardar clave privada y certificado de JRE Productions
    with open("jre_key.pem", "wb") as f:
        f.write(jre_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("jre_cert.pem", "wb") as f:
        f.write(jre_cert.public_bytes(serialization.Encoding.PEM))

# Función para registrar un nuevo usuario y generar su certificado
def register_user(username):
    # Cargar clave privada y certificado de JRE Productions
    with open("jre_key.pem", "rb") as f:
        jre_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("jre_cert.pem", "rb") as f:
        jre_cert = x509.load_pem_x509_certificate(f.read())

    # Generar clave privada y CSR para el usuario
    user_key = generate_private_key()
    user_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Los Angeles"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, username),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).sign(user_key, hashes.SHA256())

    user_cert = generate_signed_cert(jre_cert, jre_key, user_csr)

    # Guardar clave privada y certificado del usuario
    with open(f"{username}_key.pem", "wb") as f:
        f.write(user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{username}_cert.pem", "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificado generado para el usuario {username}")

# Inicializar la PKI al ejecutar el script
if __name__ == "__main__":
    initialize_pki()