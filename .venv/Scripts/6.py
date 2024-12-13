from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt
)
from bcrypt import hashpw, gensalt, checkpw

# Ініціалізація застосунку Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
jwt = JWTManager(app)


# Створення моделі User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # ROLE_USER або ROLE_ADMIN


# Створюємо базу даних
with app.app_context():
    db.create_all()


# Функція для обмеження доступу за ролями
def role_required(role):
    def wrapper(func):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") != role:
                return jsonify({"msg": "Access denied"}), 403
            return func(*args, **kwargs)

        return decorator

    return wrapper


# Реєстрація користувача
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if role not in ['ROLE_USER', 'ROLE_ADMIN']:
        return jsonify({"msg": "Invalid role"}), 400

    hashed_pw = hashpw(password.encode('utf-8'), gensalt())
    new_user = User(username=username, password=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201


# Логін і отримання токена
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({"msg": "Invalid credentials"}), 401

    # Генерація токена доступу з роллю
    access_token = create_access_token(identity=username, additional_claims={"role": user.role})
    return jsonify(access_token=access_token)


# Приватний маршрут для користувача ROLE_USER
@app.route('/user', methods=['GET'])
@role_required('ROLE_USER')
def user_dashboard():
    return jsonify({"msg": "Welcome, user!"})


# Приватний маршрут для користувача ROLE_ADMIN
@app.route('/admin', methods=['GET'])
@role_required('ROLE_ADMIN')
def admin_dashboard():
    return jsonify({"msg": "Welcome, admin!"})


# Основний маршрут
@app.route("/")
def home():
    return jsonify({"msg": "Welcome to the RBAC app!"})


# Запуск сервера
if __name__ == '__main__':
    app.run(debug=True)
