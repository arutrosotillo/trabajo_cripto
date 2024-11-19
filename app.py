from flask import Flask, render_template, session, redirect, url_for, request, flash
import logging
import sqlite3
import bcrypt
import hmac
import hashlib
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from generate_and_store_hmac_key import load_key

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Define the directory where keys will be stored
KEYS_DIR = "KEYS_DIR"

# Ensure the directory exists
os.makedirs(KEYS_DIR, exist_ok=True)

# Cargar la clave secreta para HMAC
try:
    secret_key = load_key()
except FileNotFoundError:
    raise ValueError("Clave secreta no encontrada. Por favor, genera una usando generate_and_store_key.py.")

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
    """Generate and store a key pair for a user."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the private key to a file (USERS LOCAL DEVICE)
    private_key_file = os.path.join(KEYS_DIR, f"{username}_private_key.pem")
    with open(private_key_file, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    # Generate and store the public key
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save the public key to the database
    conn = get_db_connection()
    conn.execute("UPDATE users SET public_key = ? WHERE username = ?", (public_key_pem.decode("utf-8"), username))
    conn.commit()
    conn.close()
    print(f"Public key stored for user: {username}")



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

    try:
        # Extraer clave pública de Joe Rogan
        conn = get_db_connection()
        cursor = conn.execute("SELECT public_key FROM users WHERE username = ?", ("Joe Rogan",))
        result = cursor.fetchone()

        if result is None:
            raise ValueError(f"No public key found for user {'Joe Rogan'}.")
        
        public_key_pem = result[0]  # Assuming the public_key column stores the PEM-encoded key as text
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        # Encrypt the message using the recipient's public key
        encrypted_message = public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Generar HMAC del mensaje cifrado
        h = hmac.new(secret_key, encrypted_message, hashlib.sha256)
        message_hmac = h.hexdigest()  # HMAC en formato hexadecimal

        # Guardar mensaje cifrado y HMAC en la base de datos
        conn.execute(
            "INSERT INTO messages (user_id, message, hmac) VALUES (?, ?, ?)",
            (session['user_id'], encrypted_message, message_hmac),
        )
        conn.commit()
        conn.close()

    except Exception as e:
        raise ValueError(f"Failed to encrypt message for {"Joe Rogan"}: {e}")


    flash('Mensaje enviado con éxito', 'success') 
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

    # Obtener el mensaje cifrado y el HMAC de la base de datos
    result = conn.execute(
        "SELECT message, hmac FROM messages WHERE message_id = ?", 
        (message_id,)
    ).fetchone()
    conn.close()

    if result:
        encrypted_message = result['message']
        stored_hmac = result['hmac']

        # Verificar HMAC del mensaje cifrado
        h = hmac.new(secret_key, encrypted_message, hashlib.sha256)
        calculated_hmac = h.hexdigest()

        if not hmac.compare_digest(stored_hmac, calculated_hmac):
            flash("Error: La autenticidad del mensaje no pudo ser verificada.", 'danger')
            return redirect(url_for('mensajes'))

        # Continuar con el descifrado si el HMAC es válido
        private_key_file = os.path.join(KEYS_DIR, f"{user['username']}_private_key.pem")
        if not os.path.exists(private_key_file):
            raise ValueError(f"No private key file found for user {user}.")

        try:
            # Cargar la clave privada
            with open(private_key_file, "rb") as file:
                private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None,
                )

            # Descifrar el mensaje
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

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
                decrypted_message=decrypted_message.decode('utf-8'), 
                decrypted_message_id=message_id
            )
        except Exception as e:
            print(f"Error al descifrar el mensaje: {str(e)}")
            flash("Error al descifrar el mensaje.", 'danger')
            return redirect(url_for('mensajes'))
    else:
        print("Mensaje no encontrado en la base de datos")
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