from flask import Flask, render_template, session, redirect, url_for, request, flash
import logging
import sqlite3
import bcrypt
import hmac
import hashlib
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Cargar la clave desde el archivo en lugar de generar una nueva cada vez
with open('key.key', 'rb') as key_file:
    key = key_file.read()

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

    # Cargar la clave desde el archivo
    with open('key.key', 'rb') as key_file:
        key = key_file.read()

    # Aquí empieza la lógica para cifrar (USANDO FERNET)
    f = Fernet(key)
    token = f.encrypt(message.encode('utf-8'))

    # Verifica qué se está almacenando
    print(f"Mensaje cifrado (bytes): {token}")
    print(f"Tipo de dato del mensaje cifrado: {type(token)}")

    conn = get_db_connection()
    conn.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", 
                 (session['user_id'], token))
    conn.commit()
    conn.close()
    flash('Mensaje enviado con éxito', 'success') 
    return redirect(url_for('index'))



@app.route('/decrypt/<int:message_id>', methods=['POST'])
def decrypt(message_id):
    print("Estoy dentro de la función decrypt")

    if 'user_id' not in session:
        flash('Debes iniciar sesión para descifrar mensajes.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if user['username'] != 'joerogan':
        flash("No tienes permisos para descifrar este mensaje.", 'danger')
        return redirect(url_for('mensajes'))

    # Obtener el mensaje cifrado de la base de datos usando message_id
    message = conn.execute("SELECT message FROM messages WHERE message_id = ?", (message_id,)).fetchone()
    conn.close()

    if message:
        # Verificar el mensaje cifrado recuperado
        encrypted_message = message['message']
        print(f"Mensaje cifrado recuperado: {encrypted_message}")
        print(f"Tipo de dato del mensaje cifrado recuperado: {type(encrypted_message)}")

        # Usar la clave global para descifrar
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(encrypted_message)
            print(f"Mensaje descifrado correctamente: {decrypted_message.decode('utf-8')}")

            conn = get_db_connection()
            messages = conn.execute('''
                SELECT message_id, users.username, messages.message
                FROM messages 
                JOIN users ON messages.user_id = users.id
            ''').fetchall()
            conn.close()

            return render_template('mensajes.html', messages=messages, decrypted_message=decrypted_message.decode('utf-8'), decrypted_message_id=message_id)
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



# Esta funcion sera para comprobar que el mensaje no haya sido alterado con un hmac
def verify_message(key, message, hmac_given):
    hmac_verifier = hmac.new(key, message, hashlib.sha256)
    return hmac_verifier.hexdigest() == hmac_given
    





if __name__ == '__main__':
    app.run(debug=True)