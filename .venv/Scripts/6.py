from flask import Flask, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import request, abort

app = Flask(__name__)
app.secret_key = "supersecretkey"


# Налаштування автентифікації
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Користувачі та ролі (імітована база даних)
users = {
    "admin": {"password": "admin123", "role": "ROLE_ADMIN"},
    "user": {"password": "user123", "role": "ROLE_USER"}
}


# Клас користувача для Flask-Login
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role


# Завантаження користувача
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        user_data = users[user_id]
        return User(id=user_id, role=user_data["role"])
    return None


# Перевірка ролі
def role_required(role):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role:
                abort(403)  # Доступ заборонено
            return func(*args, **kwargs)

        return wrapper

    return decorator


# Головна сторінка
@app.route("/")
def home():
    return "Welcome to RBAC App! <a href='/login'>Login</a>"


# Сторінка для User
@app.route("/user", endpoint="user_endpoint")
@login_required
@role_required("ROLE_USER")
def user_page():
    return f"Hello User, {current_user.id}! <a href='/logout'>Logout</a>"


# Сторінка для Admin
@app.route("/admin", endpoint="admin_endpoint")
@login_required
@role_required("ROLE_ADMIN")
def admin_page():
    return f"Hello Admin, {current_user.id}! <a href='/logout'>Logout</a>"


# Сторінка входу
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users.get(username)

        if user and user["password"] == password:
            login_user(User(id=username, role=user["role"]))
            return redirect(url_for("home"))
        return "Invalid credentials. Try again."

    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''


# Вихід із системи
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# Обробка забороненого доступу
@app.errorhandler(403)
def forbidden_page(e):
    return "403 Access Forbidden", 403


# Запуск додатка
if __name__ == "__main__":
    app.run(debug=True)
