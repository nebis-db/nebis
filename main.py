from flask import Flask, request, jsonify, send_from_directory, render_template
import json
import os
import requests
from urllib.parse import urlparse
import bcrypt
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer
import shutil
import concurrent.futures
import msgpack
from dotenv import load_dotenv
import logging
import re
from collections import defaultdict
import time

app = Flask(__name__)
load_dotenv()

# Configuración del registro de errores
logging.basicConfig(filename='app.log', level=logging.ERROR)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Serializer para tokens de confirmación de correo
s = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))

# Limitar intentos de inicio de sesión
login_attempts = defaultdict(lambda: {'attempts': 0, 'last_attempt_time': 0})
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # 5 minutos

def validate_username(username):
    """Valida que el nombre de usuario sea alfanumérico y tenga al menos 3 caracteres."""
    if not username.isalnum() or len(username) < 3:
        raise ValueError("El nombre de usuario debe ser alfanumérico y tener al menos 3 caracteres.")

def validate_password(password):
    """Valida que la contraseña tenga al menos 8 caracteres, incluyendo letras y números."""
    if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        raise ValueError("La contraseña debe tener al menos 8 caracteres, incluyendo letras y números.")

def validate_email(email):
    """Valida que el correo electrónico tenga un formato correcto."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise ValueError("El correo electrónico no es válido.")

class NebisDB:
    """Clase para manejar la base de datos Nebis, incluyendo conexión y operaciones CRUD."""

    def __init__(self, db_url=None, filename='data.json'):
        """Inicializa la base de datos, carga datos y crea una copia de seguridad si es necesario."""
        self.filename = filename
        self.data = self.load_data()
        self.remote_url = None
        self.username = None
        self.password = None
        self.data_in_memory = {}
        if db_url:
            self.connect(db_url)
        self.create_backup()
    
    def create_backup(self):
        """Crea una copia de seguridad del archivo de usuarios si existe."""
        users_file = 'users.json'
        if os.path.exists(users_file):
            backup_file = 'users_backup.json'
            shutil.copy(users_file, backup_file)

    def is_connected(self):
        """Verifica si hay una conexión activa a la base de datos."""
        return self.username is not None and self.password is not None

    def load_data(self, filename=None):
        """Carga datos desde un archivo local, ya sea en formato JSON o MessagePack."""
        if filename is None:
            filename = self.filename

        if os.path.exists(filename):
            try:
                if filename.endswith('.msgpack'):
                    with open(filename, 'rb') as f:
                        return msgpack.load(f, raw=False)  # Cargar en formato MessagePack
                else:
                    with open(filename, 'r') as f:
                        return json.load(f)  # Cargar en formato JSON
            except (msgpack.exceptions.UnpackException, json.JSONDecodeError) as e:
                logging.error(f"Error al cargar datos desde {filename}: {e}")
                return {}
        return {}

    def connect(self, db_url):
        """Conecta a la base de datos remota usando la URL proporcionada."""
        parsed_url = urlparse(db_url)
        self.username = parsed_url.username
        self.password = parsed_url.password
        self.remote_url = f"http://{parsed_url.hostname}/{parsed_url.path.lstrip('/')}.json"
        
        # Establecer el nombre del archivo sin la extensión
        self.filename = os.path.basename(parsed_url.path)  # Esto tomará solo el nombre del archivo sin la extensión
        self.load_remote_data()

    def load_remote_data(self, retries=3, timeout=10):
        """Carga datos desde la base de datos remota con reintentos."""
        try:
            for attempt in range(retries):
                response = requests.get(f"https://nebisdb.pythonanywhere.com/files/{self.filename}.json", auth=(self.username, self.password), timeout=timeout)
                if response.status_code == 200:
                    self.data = response.json()
                    return
                else:
                    logging.error(f"Error al cargar datos remotos: {response.status_code}")
                
                # Espera un tiempo antes de reintentar
                time.sleep(2 ** attempt)  # Exponencial backoff

            # Si después de varios intentos no se logra la conexión, maneja el error
            self.data = {}
            logging.error("Error al cargar datos remotos después de múltiples intentos.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error al conectar a la base de datos remota: {e}")
            self.data = {}

    def _save_data(self):
        """Guarda los datos en disco, tanto localmente como en el servidor remoto."""
        try:
            self.save_data()  # Guarda en archivo local
            self._save_to_remote(self.data_in_memory)  # Luego guarda en el servidor
        except Exception as e:
            logging.error(f"Error al guardar los datos: {e}")

    def save_data(self, filename=None, data=None):
        """Guarda datos en un archivo local, ya sea en formato JSON o MessagePack."""
        if filename is None:
            filename = self.filename
        if data is None:
            data = self.data_in_memory  # Usar los datos en memoria

        try:
            if filename.endswith('.msgpack'):
                with open(filename, 'wb') as f:
                    msgpack.dump(data, f)
            else:
                with open(filename, 'w') as f:
                    json.dump(data, f)
        except IOError as e:
            logging.error(f"Error al guardar datos en {filename}: {e}")

    def _save_to_remote(self, data):
        """Guarda datos en el servidor de forma asincrónica."""
        try:
            if self.remote_url:
                response = requests.post(self.remote_url, json=data, auth=(self.username, self.password))
                if response.status_code != 200:
                    logging.error(f"Error al guardar datos remotos: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error al conectar al servidor remoto: {e}")

    def _save_to_local(self, filename, data):
        """Guarda datos en un archivo local, actualizando los datos existentes."""
        existing_data = self.load_data(filename)
        existing_data.update(data)
        try:
            with open(filename, 'w') as f:
                json.dump(existing_data, f)
        except IOError as e:
            logging.error(f"Error al guardar datos en {filename}: {e}")

    def add_entry(self, key: str, value: str):
        """Agrega una entrada a la base de datos en memoria y la guarda en segundo plano."""
        if not key or not value:
            raise ValueError("La clave y el valor no pueden estar vacíos.")

        # Guardar en memoria
        self.data_in_memory[key] = value

        # Llamar a la función para guardar en segundo plano
        self._save_in_background()

    def _save_in_background(self):
        """Guarda los datos en segundo plano usando un ThreadPoolExecutor."""
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self._save_data)
            future.result()  # Esperar hasta que el hilo termine (puedes omitir esto si quieres que sea completamente asincrónico)

    def _save_entry(self, db_file_path, db_data):
        """Guarda una entrada en un archivo específico."""
        try:
            with open(db_file_path, 'w') as f:
                json.dump(db_data, f)
        except IOError as e:
            logging.error(f"Error al guardar datos en {db_file_path}: {e}")
            return {"error": "Error al guardar la entrada."}, 500

    def get_entry(self, key):
        """Obtiene una entrada de la base de datos por su clave."""
        value = self.data.get(key, None)
        if value is None:
            return {"error": "Entrada no encontrada."}, 404
        return value

    def register(self, username, password, email):
        """Registra un nuevo usuario, validando sus datos y enviando un correo de confirmación."""
        validate_username(username)
        validate_password(password)
        validate_email(email)

        users_file = 'users.json'
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
            if username in users:
                return {"error": "El nombre de usuario ya está en uso."}

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user_directory = f"databases/{username}"
        os.makedirs(user_directory, exist_ok=True)

        self.store_user(username, hashed_password, email)
        self.send_confirmation_email(email, username)

        return {"message": "Cuenta creada exitosamente! Por favor, verifica tu correo para confirmar tu cuenta."}

    def store_user(self, username, password, email):
        """Almacena la información del usuario en el archivo de usuarios."""
        users_file = 'users.json'
        users = self.load_data(users_file)

        users[username] = {
            "password": password,
            "email": email,
            "status": "unconfirmed",
            "databases": []
        }

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self._save_users, users_file, users)
            future.result()

    def _save_users(self, users_file, users):
        """Guarda la lista de usuarios en el archivo correspondiente."""
        try:
            with open(users_file, 'w') as f:
                json.dump(users, f)
        except IOError as e:
            logging.error(f"Error al guardar usuarios en {users_file}: {e}")

    def send_confirmation_email(self, email, username):
        """Envía un correo de confirmación al usuario después del registro."""
        token = s.dumps(email, salt='email-confirmation')
        confirm_url = f"https://nebisdb.pythonanywhere.com/confirm/{token}"
        subject = "Confirma tu cuenta en Nebis"
        body = f"Hola {username},\n\nPor favor, confirma tu cuenta haciendo clic en el siguiente enlace:\n{confirm_url}\n\nSi no solicitaste este registro, ignora este correo."

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USERNAME
        msg['To'] = email

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        except Exception as e:
            logging.error(f"Error al enviar correo de confirmación: {e}")

    def confirm_account(self, token):
        """Confirma la cuenta del usuario usando el token proporcionado."""
        try:
            email = s.loads(token, salt='email-confirmation', max_age=3600)
            users_file = 'users.json'
            if os.path.exists(users_file):
                with open(users_file, 'r') as f:
                    users = json.load(f)
                for user, data in users.items():
                    if data['email'] == email:
                        data['status'] = 'confirmed'
                        break
                with open(users_file, 'w') as f:
                    json.dump(users, f)
            return "Cuenta confirmada exitosamente."
        except Exception as e:
            logging.error(f"Error al confirmar cuenta: {e}")
            return "Error al confirmar la cuenta. Por favor, intenta de nuevo más tarde."

    def get_nebis_url(self):
        """Devuelve la URL de conexión a la base de datos Nebis."""
        if self.username and self.password:
            return f"nebis://{self.username}:{self.password}@https://nebisdb.pythonanywhere.com/{self.filename}"
        else:
            return "Error: No se ha conectado a una base de datos."

    def validate_user(self, username, password):
        """Valida las credenciales del usuario durante el inicio de sesión."""
        users_file = 'users.json'
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
            user_data = users.get(username)
            if user_data:
                if bcrypt.checkpw(password.encode('utf-8'), user_data["password"].encode('utf-8')):
                    if user_data["status"] == "confirmed":
                        return True
                    else:
                        return False
        return False

    def get_user_databases(self, username):
        """Devuelve la lista de bases de datos asociadas a un usuario."""
        databases = []
        users_file = 'users.json'
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
            user_data = users.get(username)
            if user_data:
                databases = user_data.get("databases", [])
        return databases
    
    def add_database(self, username, filename):
        """Agrega una nueva base de datos para el usuario especificado."""
        users_file = 'users.json'
        users = self.load_data(users_file)

        if username in users:
            if "databases" not in users[username]:
                users[username]["databases"] = []
            users[username]["databases"].append(filename)

            user_directory = f"databases/{username}"
            self.save_data(os.path.join(user_directory, filename), {})
            self.save_data(users_file, users)
            return True
        return False

    def delete_database(self, username, filename):
        """Elimina una base de datos del usuario especificado."""
        users_file = 'users.json'
        users = self.load_data(users_file)

        if username in users:
            if filename in users[username].get("databases", []):
                users[username]["databases"].remove(filename)
                self.save_data(users_file, users)
                db_file_path = os.path.join('databases', username, filename)
                if os.path.exists(db_file_path):
                    os.remove(db_file_path)
                return True
        return False
    
    def user_has_permission(self, username, db_name):
        """Verifica si el usuario tiene permiso para acceder a la base de datos especificada."""
        users_file = 'users.json'
        if not os.path.exists(users_file):
            return False

        with open(users_file, 'r') as f:
            users = json.load(f)

        user = users.get(username)
        if user:
            if db_name in user.get('databases', []):
                return True

        return False

# Instancia de la base de datos
db = NebisDB()

@app.route('/register', methods=['POST'])
def register():
    """Endpoint para registrar un nuevo usuario."""
    content = request.json
    username = content.get('username')
    password = content.get('password')
    email = content.get('email')

    if not username or not password or not email:
        return jsonify({"error": "Faltan datos para el registro."}), 400

    try:
        validate_username(username)
        validate_password(password)
        validate_email(email)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    result = db.register(username, password, email)
    if "error" in result:
        return jsonify({"error": "Error en el registro. Por favor, intenta de nuevo."}), 400

    return jsonify({"message": result["message"]}), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint para iniciar sesión de un usuario."""
    content = request.json
    username = content.get('username')
    password = content.get('password')

    current_time = time.time()
    user_attempts = login_attempts[username]

    # Check if the user is currently blocked
    if user_attempts['attempts'] >= MAX_ATTEMPTS:
        if current_time - user_attempts['last_attempt_time'] < BLOCK_TIME:
            return jsonify({"error": "Demasiados intentos fallidos. Intenta de nuevo más tarde."}), 403
        else:
            # Reset attempts after block time
            user_attempts['attempts'] = 0

    if db.validate_user(username, password):
        user_attempts['attempts'] = 0  # Reset attempts on successful login
        return jsonify({"message": "Inicio de sesión exitoso."}), 200
    else:
        user_attempts['attempts'] += 1
        user_attempts['last_attempt_time'] = current_time
        return jsonify({"error": "Credenciales inválidas."}), 401

@app.route('/get_user_databases', methods=['GET'])
def get_user_databases():
    """Endpoint para obtener las bases de datos de un usuario."""
    username = request.args.get('username')
    databases = db.get_user_databases(username)
    return jsonify({"databases": databases}), 200

@app.route('/delete_database', methods=['DELETE'])
def delete_database():
    """Endpoint para eliminar una base de datos de un usuario."""
    content = request.json
    username = content.get('username')
    filename = content.get('filename')

    if db.delete_database(username, filename):
        return jsonify({"message": "Base de datos eliminada exitosamente."}), 200
    else:
        return jsonify({"error": "No se pudo eliminar la base de datos."}), 400

@app.route('/get_nebis_url', methods=['GET'])
def get_nebis_url():
    """Endpoint para obtener la URL de conexión a la base de datos Nebis."""
    username = request.args.get('username')
    database_name = request.args.get('database')
    password = request.args.get('password')

    if db.is_connected() and db.username == username and db.password == password:
        db_url = f"nebis://{username}:{password}@https://nebisdb.pythonanywhere.com/{database_name}"
        return jsonify({"nebis_url": db_url}), 200
    else:
        return jsonify({"error": "No se ha conectado a una base de datos o credenciales incorrectas."}), 400

@app.route('/connect', methods=['POST'])
def connect():
    """Endpoint para conectar a una base de datos usando la URL proporcionada."""
    content = request.json
    db_url = content.get('db_url')

    if not db_url:
        return jsonify({"error": "Faltan datos para la conexión."}), 400

    try:
        db.connect(db_url)
        return jsonify({"message": "Connected to the database!"}), 200
    except Exception as e:
        logging.error(f"Error al conectar a la base de datos: {e}")
        return jsonify({"error": "Error al conectar a la base de datos."}), 500

@app.route('/add', methods=['POST'])
def add_entry():
    """Endpoint para agregar una entrada a la base de datos."""
    content = request.json

    if not content or 'key' not in content or 'value' not in content or 'db_name' not in content:
        return jsonify({"error": "Datos inválidos. Se requiere 'key', 'value', y 'db_name'."}), 400

    db_name = content['db_name'] + '.json'
    key = content['key']
    value = content['value']
    username = content.get('username')

    db_file_path = os.path.join('databases', username, f"{db_name}")

    if not db.user_has_permission(username, db_name):
        return jsonify({"error": "No tienes permiso para acceder a esta base de datos."}), 403

    if not os.path.exists(db_file_path):
        return jsonify({"error": "La base de datos no existe."}), 404

    db_data = db.load_data(db_file_path)
    db_data[key] = value

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(db._save_entry, db_file_path, db_data)
        future.result()

    return jsonify({"message": "Entrada agregada exitosamente.", "db_name": db_name}), 201

@app.route('/get/<key>', methods=['GET'])
def get_entry(key):
    """Endpoint para obtener una entrada de la base de datos por su clave."""
    value = db.get_entry(key)
    if isinstance(value, dict) and "error" in value:
        return jsonify({"error": "Entrada no encontrada."}), 404
    return jsonify({key: value}), 200

@app.route('/files/<path:filename>', methods=['GET'])
def serve_file(filename):
    """Endpoint para servir archivos JSON o MessagePack."""
    file_path = os.path.join('/home/nebisdb/databases', filename)
    if os.path.exists(file_path):
        if filename.endswith('.msgpack'):
            # Convertir MessagePack a JSON para la descarga
            with open(file_path, 'rb') as f:
                data = msgpack.load(f, raw=False)
            response = jsonify(data)
            response.mimetype = 'application/json'
            return response
        elif filename.endswith('.json'):
            return send_from_directory('/home/nebisdb/databases', filename)
    return jsonify({"error": "Archivo no encontrado."}), 404

@app.route('/add_database', methods=['POST'])
def add_database():
    """Endpoint para agregar una nueva base de datos para un usuario."""
    content = request.json
    username = content.get('username')
    filename = content.get('filename')
    
    if db.add_database(username, filename):
        return jsonify({"message": "Base de datos añadida exitosamente."}), 201
    else:
        return jsonify({"error": "No se pudo añadir la base de datos."}), 400

@app.route('/confirm/<token>')
def confirm_account(token):
    """Endpoint para confirmar la cuenta del usuario usando un token."""
    try:
        email = s.loads(token, salt='email-confirmation', max_age=3600)
        users_file = 'users.json'
        
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
            
            for username, data in users.items():
                if data['email'] == email:
                    data['status'] = 'confirmed'
                    break
            
            with open(users_file, 'w') as f:
                json.dump(users, f)
        
        return render_template("confirm.html", message="Cuenta confirmada exitosamente.")
    except Exception as e:
        logging.error(f"Error al confirmar cuenta: {e}")
        return render_template("confirm.html", error="Error al confirmar la cuenta. Por favor, intenta de nuevo más tarde.")

@app.route('/ping', methods=['GET'])
def ping():
    """Endpoint para verificar que el servidor está activo."""
    return jsonify({"message": "Pong!"}), 200

@app.route('/update', methods=['PUT'])
def update_entry():
    """Endpoint para actualizar una entrada en la base de datos."""
    content = request.json

    if not content or 'key' not in content or 'value' not in content or 'db_name' not in content:
        return jsonify({"error": "Datos inválidos. Se requiere 'key', 'value' y 'db_name'."}), 400

    db_name = content['db_name'] + '.json'
    key = content['key']
    value = content['value']
    username = content.get('username')

    db_file_path = os.path.join('databases', username, f"{db_name}")

    if not db.user_has_permission(username, db_name):
        return jsonify({"error": "No tienes permiso para acceder a esta base de datos."}), 403

    if not os.path.exists(db_file_path):
        return jsonify({"error": "La base de datos no existe."}), 404

    db_data = db.load_data(db_file_path)
    if key in db_data:
        db_data[key] = value
    else:
        return jsonify({"error": "Clave no encontrada en la base de datos."}), 404

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(db._save_entry, db_file_path, db_data)
        future.result()

    return jsonify({"message": "Entrada actualizada exitosamente.", "db_name": db_name}), 200

@app.route('/delete', methods=['DELETE'])
def delete_entry():
    """Endpoint para eliminar una entrada de la base de datos."""
    content = request.json

    if not content or 'key' not in content or 'db_name' not in content:
        return jsonify({"error": "Datos inválidos. Se requiere 'key' y 'db_name'."}), 400

    db_name = content['db_name'] + '.json'
    key = content['key']
    username = content.get('username')

    db_file_path = os.path.join('databases', username, f"{db_name}")

    if not db.user_has_permission(username, db_name):
        return jsonify({"error": "No tienes permiso para acceder a esta base de datos."}), 403

    if not os.path.exists(db_file_path):
        return jsonify({"error": "La base de datos no existe."}), 404

    db_data = db.load_data(db_file_path)
    if key in db_data:
        del db_data[key]
    else:
        return jsonify({"error": "Clave no encontrada en la base de datos."}), 404

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(db._save_entry, db_file_path, db_data)
        future.result()

    return jsonify({"message": "Entrada eliminada exitosamente.", "db_name": db_name}), 200

if __name__ == '__main__':
    app.run(debug=True)