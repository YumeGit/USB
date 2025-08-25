from flask import Flask, render_template, jsonify, request, redirect, url_for
from datetime import datetime
import secrets
import json
import os
import psutil
import string
from flask import send_file

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")

# Путь к файлам для пароля и истории
PASSWORD_FILE = "data/password.txt"
HISTORY_FILE = "data/history.json"

# Логин и пароль для проверки
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

def create_password(length=12):
    """Генерация безопасного пароля длиной length"""
    # Все возможные символы для пароля
    all_chars = string.ascii_letters + string.digits + string.punctuation
    # Генерация пароля
    password = ''.join(secrets.choice(all_chars) for _ in range(length))
    return password

def write_password(password):
    """Записать сгенерированный пароль в файл"""
    with open(PASSWORD_FILE, 'w', encoding='utf-8') as f:
        f.write(password)

def read_password():
    """Прочитать сгенерированный пароль из файла"""
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return ""

def log_history(password, username=""):
    """Записать историю сгенерированных паролей"""
    entry = {
        "password": password,
        "username": username,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except json.JSONDecodeError:
            pass
    history.insert(0, entry)
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)

def check_usb_authorization():
    """Проверка наличия флешки с любым именем"""
    drives = [disk.device for disk in psutil.disk_partitions() if 'removable' in disk.opts]
    for drive in drives:
        if os.path.exists(drive):
            return True  # Флешка подключена
    return False

@app.route("/")
def home():
    """Главная страница авторизации"""
    return render_template("welcome.html")

@app.route("/history")
def history_page():
    """Страница с историей паролей"""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except json.JSONDecodeError:
            pass
    return render_template("history.html", history=history)

@app.route("/generate", methods=["GET", "POST"])
def generate_password():
    """Генерация пароля"""
    if request.method == "POST":
        password = create_password()
        write_password(password)
        log_history(password)
        return jsonify({"password": password})  # Возвращаем сгенерированный пароль как JSON
    else:
        password = read_password()  # Читаем сгенерированный пароль для отображения
        return render_template("index.html", password=password)  # Страница генерации пароля (если GET запрос)

@app.route("/api/password")
def api_get_password():
    """Получить сгенерированный пароль через API"""
    return jsonify({"password": read_password()})

@app.route("/api/history")
def api_get_history():
    """Получить историю сгенерированных паролей через API"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return jsonify(json.load(f))
        except json.JSONDecodeError:
            return jsonify([])  # Пустой список, если история повреждена
    return jsonify([])

@app.route("/api/authorize", methods=["POST"])
def authorize():
    """Проверка логина, пароля или авторизация через флешку"""
    data = request.json
    username = data.get("username")
    password = data.get("password")

    # Проверка логина и пароля
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify({"authorized": True})
    
    # Проверка на наличие авторизованной флешки
    if check_usb_authorization():
        return jsonify({"authorized": True})
    
    return jsonify({"authorized": False})
@app.route("/api/token")
def generate_token_file():
    token = secrets.token_hex(16)
    filename = "access.token"
    filepath = os.path.join("data", filename)
    with open(filepath, "w") as f:
        f.write(token)
    return send_file(filepath, as_attachment=True)

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)  # Создание папки для хранения данных, если ее нет
    app.run(debug=True)
