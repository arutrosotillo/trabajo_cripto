from flask import Flask, render_template, session, redirect, url_for, request, flash
import logging
import sqlite3
import bcrypt
import hashlib
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import logging
from cryptography.fernet import Fernet


# Configuración de logging (mensajes en la terminal)
logging.basicConfig(
    level=logging.DEBUG,  # Captura todos los mensajes desde DEBUG hacia arriba
    format="%(asctime)s - %(levelname)s - %(message)s",  # Formato del log
    handlers=[
        logging.StreamHandler()  # Envía los logs a la terminal
    ]
)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Define the directory where keys will be stored
KEYS_DIR = "KEYS_DIR"

# Ensure the directory exists
os.makedirs(KEYS_DIR, exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.context_processor
def inject_is_logged_in():
    return {'is_logged_in': 'user_id' in session}

@app.route('/')
def index():
    return render_template('index.html')


def generate_user_keys(username: str):
    """Generate and store two key pairs for a user: one for encryption and one for signing."""
    # Generar par de claves para cifrado
    private_key_encrypt = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Longitud de la clave
    )
    public_key_encrypt = private_key_encrypt.public_key()

    # Generar par de claves para firma
    private_key_signature = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Longitud de la clave
    )
    public_key_signature = private_key_signature.public_key()

    # Guardar claves privadas en archivos
    private_key_encrypt_file = os.path.join(KEYS_DIR, f"{username}_private_key_encrypt.pem")
    with open(private_key_encrypt_file, "wb") as file:
        file.write(
            private_key_encrypt.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    logging.debug(f"Clave privada de cifrado almacenada en: {private_key_encrypt_file}")

    private_key_signature_file = os.path.join(KEYS_DIR, f"{username}_private_key_signature.pem")
    with open(private_key_signature_file, "wb") as file:
        file.write(
            private_key_signature.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    logging.debug(f"Clave privada de firma almacenada en: {private_key_signature_file}")

    # Convertir claves públicas a PEM
    public_key_encrypt_pem = public_key_encrypt.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_signature_pem = public_key_signature.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Guardar claves públicas en la base de datos
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET public_key_encrypt = ?, public_key_signature = ? WHERE username = ?",
        (public_key_encrypt_pem.decode("utf-8"), public_key_signature_pem.decode("utf-8"), username)
    )
    conn.commit()
    conn.close()

    logging.info(f"Claves públicas de cifrado y firma almacenadas en la base de datos para el usuario: {username}")



def generate_signature(message: str, private_key_path: str) -> bytes:
    """
    Genera una firma digital para un mensaje utilizando una clave privada.
    :param message: El mensaje que será firmado.
    :param private_key_path: Ruta de la clave privada para firmar.
    :return: La firma generada en formato bytes.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    logging.debug(f"Firma digital generada utilizando RSA con padding PSS, MGF1 y algoritmo SHA-256.")
    return signature


def verify_signature(message: str, signature: bytes, public_key_pem: str) -> bool:
    """
    Verifica una firma digital utilizando la clave pública del remitente.
    :param message: El mensaje original.
    :param signature: La firma digital que será verificada.
    :param public_key_pem: Clave pública en formato PEM.
    :return: True si la firma es válida, False si no.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logging.info("Firma digital verificada con éxito.")
        return True
    except Exception as e:
        logging.error(f"Error verificando la firma: {e}")
        return False


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # El hash es efectivo para guardar contraseñas, porque si alguien accede a la base de datos, aunque la funcion de hash sea conocida, no va a poder "unhash" la contraseña.
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Log para mostrar el hash de la contraseña (no recomendado en producción)
        logging.info(f"Hash de la contraseña generada para {username}: {hashed_password}")

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            # Generar y almacenar las claves de cifrado para el usuario
            generate_user_keys(username)
            flash('Registro exitoso', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Log para indicar que se ha recibido la solicitud de inicio de sesión
        logging.info(f"Intento de inicio de sesión para: {username}")

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user:
            # Log para indicar que se encontró el usuario en la base de datos
            logging.info(f"Usuario {username} encontrado en la base de datos")

            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['user_id'] = user['id']
                flash('Inicio de sesión exitoso', 'success')
                return redirect(url_for('index'))
            else:
                flash('Contraseña incorrecta', 'danger')
        else:
            flash('El nombre de usuario no existe', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión', 'success')
    return redirect(url_for('index'))


@app.route('/submit_message', methods=['POST'])
def submit_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    message = request.form['message']
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()

    try:
        # Generar la firma digital usando clave privada de firma
        private_key_signature_path = os.path.join(KEYS_DIR, f"{user['username']}_private_key_signature.pem")
        if not os.path.exists(private_key_signature_path):
            raise ValueError("Clave privada de firma no encontrada para el usuario actual.")

        signature = generate_signature(message, private_key_signature_path)

        # Generar una clave simétrica para cifrar el mensaje
        symmetric_key = Fernet.generate_key()
        fernet_cipher = Fernet(symmetric_key)

        # Cifrar el mensaje con la clave simétrica
        encrypted_message = fernet_cipher.encrypt(message.encode('utf-8'))

        print("Se ha cifrado bien el mensaje")
        # Cifrar la clave simétrica con la clave pública de Joe Rogan
        cursor = conn.execute("SELECT public_key_encrypt FROM users WHERE username = ?", ("Joe Rogan",))
        result = cursor.fetchone()

        if result is None:
            raise ValueError("Clave pública de cifrado de Joe Rogan no encontrada.")

        public_key_encrypt_pem = result[0]
        public_key_encrypt = serialization.load_pem_public_key(public_key_encrypt_pem.encode("utf-8"))

        encrypted_symmetric_key = public_key_encrypt.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print("se ha cifrado bien la clave simetrica")
        # Guardar mensaje cifrado, firma y clave cifrada en la base de datos
        conn.execute(
            "INSERT INTO messages (user_id, message, signature, encrypted_key) VALUES (?, ?, ?, ?)",
            (user_id, encrypted_message, signature.hex(), encrypted_symmetric_key),
        )
        conn.commit()
        conn.close()

    except Exception as e:
        logging.error(f"Error en submit_message: {e}")
        flash('Error enviando el mensaje.', 'danger')
        return redirect(url_for('index'))

    flash('Mensaje enviado y firmado con éxito.', 'success')
    return redirect(url_for('index'))



@app.route('/decrypt/<int:message_id>', methods=['POST'])
def decrypt(message_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para descifrar mensajes.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if user['username'] != 'Joe Rogan':
        flash("No tienes permisos para descifrar este mensaje.", 'danger')
        return redirect(url_for('mensajes'))

    # Obtener el mensaje cifrado, clave cifrada, firma y usuario emisor de la base de datos
    result = conn.execute(
        "SELECT message, encrypted_key, signature, user_id FROM messages WHERE message_id = ?",
        (message_id,)
    ).fetchone()
    conn.close()

    if result:
        encrypted_message = result['message']
        encrypted_key = result['encrypted_key']
        signature = bytes.fromhex(result['signature'])
        sender_id = result['user_id']


        # Descifrar la clave simétrica con la clave privada de Joe Rogan
        private_key_file = os.path.join(KEYS_DIR, f"{user['username']}_private_key_encrypt.pem")
        if not os.path.exists(private_key_file):
            raise ValueError(f"No se encontró la clave privada de cifrado para {user['username']}.")

        try:
            with open(private_key_file, "rb") as file:
                private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None,
                )

            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Descifrar el mensaje con Fernet
            fernet_cipher = Fernet(symmetric_key)
            decrypted_message = fernet_cipher.decrypt(encrypted_message).decode("utf-8")

            # Verificar la firma digital usando clave pública del remitente
            conn = get_db_connection()
            result = conn.execute("SELECT public_key_signature FROM users WHERE id = ?", (sender_id,)).fetchone()
            conn.close()

            if not result:
                flash("No se encontró la clave pública de firma del emisor.", 'danger')
                return redirect(url_for('mensajes'))

            sender_public_key_pem = result['public_key_signature']

            if not verify_signature(decrypted_message, signature, sender_public_key_pem):
                flash("Error: La firma digital no es válida.", 'danger')
                return redirect(url_for('mensajes'))

            flash("Mensaje descifrado y firma verificada con éxito.", 'success')

            # Mostrar mensajes descifrados
            conn = get_db_connection()
            messages = conn.execute('''
                SELECT message_id, users.username, messages.message
                FROM messages 
                JOIN users ON messages.user_id = users.id
            ''').fetchall()
            conn.close()

            return render_template(
                'mensajes.html', 
                messages=messages, 
                decrypted_message=decrypted_message, 
                decrypted_message_id=message_id
            )

        except Exception as e:
            logging.error(f"Error al descifrar el mensaje: {e}")
            flash("Error al descifrar el mensaje.", 'danger')
            return redirect(url_for('mensajes'))

    else:
        logging.error("Mensaje no encontrado en la base de datos")
        flash("Mensaje no encontrado.", 'danger')
        return redirect(url_for('mensajes'))



@app.route('/mensajes')
def mensajes():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    messages = conn.execute('''
        SELECT message_id, users.username, messages.message
        FROM messages 
        JOIN users ON messages.user_id = users.id
    ''').fetchall()
    conn.close()

    return render_template('mensajes.html', messages=messages)



if __name__ == '__main__':
    app.run(debug=True)

""" 
Resumen del flujo híbrido:
Genera firmar digital
Generar una clave simétrica para cifrar el mensaje.
Cifrar el mensaje con Fernet usando la clave simétrica.
Cifrar la clave simétrica con RSA usando la clave pública del destinatario.
Guardar el mensaje cifrado, la clave simétrica cifrada y la firma digital.
Durante el descifrado:
Descifrar la clave simétrica con RSA.
Usar la clave simétrica para descifrar el mensaje.
Verificar la firma
"""