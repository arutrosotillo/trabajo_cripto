import datetime
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography import x509

# Configuración del directorio para almacenar los certificados y claves
CERT_DIR = "CERT_DIR"
PKI_CERT = "PKI_CERT"
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(PKI_CERT, exist_ok=True)

def create_root_certificate():
    """Crea la CA raíz (Spotify)."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Spotify"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Spotify Root CA"),
    ])
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(root_key, hashes.SHA256())
    
    # Guardar clave privada y certificado
    save_key_and_cert(root_key, root_cert, "spotify_root", CERT_DIR)
    return root_key, root_cert


def create_intermediate_certificate(root_key, root_cert):
    """Crea la CA subordinada (JRE Productions)."""
    int_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JRE Productions"),
        x509.NameAttribute(NameOID.COMMON_NAME, "JRE Intermediate CA"),
    ])
    int_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        int_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 5)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).sign(root_key, hashes.SHA256())
    
    # Guardar clave privada y certificado
    save_key_and_cert(int_key, int_cert, "jre_intermediate", CERT_DIR)
    return int_key, int_cert


def create_user_certificate(username, int_key, int_cert):
    """Crea un certificado final para el usuario."""
    user_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JRE Productions"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    user_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        int_cert.subject
    ).public_key(
        user_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(int_key, hashes.SHA256())
    
    # Guardar clave privada y certificado
    save_key_and_cert(user_key, user_cert, username, PKI_CERT)
    return user_key, user_cert


def save_key_and_cert(key, cert, name, folder):
    """Guarda una clave privada y un certificado en archivos."""
    key_path = os.path.join(folder, f"{name}_key.pem")
    cert_path = os.path.join(folder, f"{name}_cert.pem")

    # Guardar clave privada
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    # Guardar certificado
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


# Crear CA raíz e intermedia
root_key, root_cert = create_root_certificate()
int_key, int_cert = create_intermediate_certificate(root_key, root_cert)
