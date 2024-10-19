import logging
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3

# Configuración del log
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Función para conectar con la base de datos
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Crear tabla de usuarios si no existe
def create_user_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Ruta para el registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Log para indicar que se ha recibido la solicitud de registro
        logging.info(f"Registro de usuario: {username}")

        # Hashear la contraseña antes de almacenarla
        # El hash es efectivo para guardar contraseñas, porque si alguien  accede a la base de datos, aunque la funcion de hash sea conocida, no va a poder "unhash" la contraseña.
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

# Ruta para el login de usuarios
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
            
            # Verificar la contraseña
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                logging.info(f"Inicio de sesión exitoso para {username}")
                flash('Inicio de sesión exitoso', 'success')
                return redirect(url_for('index'))
            else:
                logging.warning(f"Contraseña incorrecta para {username}")
                flash('Nombre de usuario o contraseña incorrectos', 'danger')
        else:
            logging.warning(f"Nombre de usuario {username} no encontrado")
            flash('Nombre de usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')

# Ruta principal
@app.route('/')
def index():
    return render_template('index.html')

# Inicializar la tabla de usuarios al inicio de la aplicación
create_user_table()

if __name__ == '__main__':
    app.run(debug=True)
