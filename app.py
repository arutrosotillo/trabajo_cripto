from flask import Flask, render_template, session, redirect, url_for, request, flash
import logging
import sqlite3
import bcrypt
from Crypto.Cipher import AES # para cifrar y descifrar
from Crypto.Random import get_random_bytes


app = Flask(__name__)
app.secret_key = 'your_secret_key'



def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.context_processor #Esto es para que el header sepa en cualquier html si el usuario está logueado o no
def inject_user():
    return dict(is_logged_in='user_id' in session)

@app.route('/')
def index():
    is_logged_in = 'user_id' in session  # Suponiendo que guardas el ID del usuario en la sesión
    return render_template('index.html', is_logged_in=is_logged_in)

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

    # Aquí empieza la lógica para cifrar
    key = b'123456789' # Use a stored / generated key
    data = message.encode('utf-8')

    cipher_encrypt = AES.new(key, AES.MODE_CFB) # Utiliza el modo CFB
    ciphered_bytes = cipher_encrypt.encrypt(data)

    # Esta son nuestros datos cifrados
    iv = cipher_encrypt.iv
    ciphered_data = ciphered_bytes

    # Aquí puedes agregar la lógica para guardar el mensaje en la base de datos
    conn = get_db_connection()
    conn.execute("INSERT INTO messages (user_id, message, iv) VALUES (?, ?, ?)", 
                 (session['user_id'], ciphered_data, iv))
    conn.commit()
    conn.close()
    flash('Mensaje enviado con éxito', 'success')
    return redirect(url_for('index'))


@app.route('/mensajes')
def mensajes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    messages = conn.execute('''
        SELECT users.username, messages.message 
        FROM messages 
        JOIN users ON messages.user_id = users.id
    ''').fetchall()
    conn.close()
    
    return render_template('mensajes.html', messages=messages)






if __name__ == '__main__':
    app.run(debug=True)