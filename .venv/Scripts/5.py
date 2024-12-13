import datetime
import jwt
from flask import Flask, request, jsonify
import getpass
app = Flask(__name__)

# Секретний ключ для підпису і верифікації токенів
SECRET_KEY = 'your_secret_key'

# Дані користувачів
username_input = input("Введіть ім'я користувача: ")
password_input = input("Введіть пароль: ")

USER_DATA = {
    "username": username_input,
    "password": password_input
}


# Функція для аутентифікації користувача
def verify_user(username, password):
    """Перевіряє логін та пароль користувача"""
    return username == USER_DATA["username"] and password == USER_DATA["password"]


# Функція створення JWT
def generate_jwt(username):
    """Генерує JWT токен для переданого користувача"""
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Термін дії токена 1 година
    payload = {
        "username": username,
        "exp": expiration_time  # Термін закінчення валідності токену
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# Функція розшифрування та перевірки токена
def decode_jwt(token):
    """Перевіряє дані токену JWT"""
    try:
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded_payload, None
    except jwt.ExpiredSignatureError:
        return None, "Токен прострочений"
    except jwt.InvalidTokenError:
        return None, "Недійсний токен"


# Маршрут для логіну
@app.route('/login', methods=['POST'])
def login():
    """Приймає логін і пароль. Повертає JWT токен у разі успішної аутентифікації"""
    data = request.json  # Отримання JSON-даних з тіла запиту
    username = data.get('username')
    password = data.get('password')

    # Перевіряємо логін та пароль
    if verify_user(username, password):
        token = generate_jwt(username)  # Генеруємо JWT токен
        return jsonify({"token": token}), 200  # Повертаємо токен у JSON форматі
    else:
        # Невдала аутентифікація
        return jsonify({"message": "Невірний логін або пароль"}), 401


# Захищений ресурс
@app.route('/protected', methods=['GET'])
def protected():
    """Захищений ресурс. Доступ лише при наявності валідного токена."""
    token = request.headers.get('Authorization')  # Отримуємо токен із заголовку

    if not token:
        return jsonify({"message": "Токен відсутній"}), 401

    decoded_payload, error = decode_jwt(token)  # Розшифрування токену
    if error:
        return jsonify({"message": error}), 401  # Помилка в токені (наприклад, прострочений токен)

    # У разі успішного доступу повертаємо привітання
    return jsonify({"message": f"Вітаємо, {decoded_payload['username']}!"}), 200


if __name__ == '__main__':
    app.run(debug=True)  # Запускаємо сервер у режимі розробки
