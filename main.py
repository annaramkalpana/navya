
SECRET_KEY = "super-secret-key"
SQLALCHEMY_DATABASE_URI = "sqlite:///users.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'your_email@gmail.com'
MAIL_PASSWORD = 'app_password'
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))
    is_verified = db.Column(db.Boolean, default=False)
from flask_login import current_user
from flask import abort
from functools import wraps

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

from config import *
from models import db, User
from decorators import role_required

app = Flask(__name__)
app.config.from_object('config')

db.init_app(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    hashed_pw = generate_password_hash(data['password'])

    user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_pw,
        role=data['role']
    )

    db.session.add(user)
    db.session.commit()

    token = serializer.dumps(user.email, salt='email-verify')
    link = url_for('verify_email', token=token, _external=True)

    msg = Message("Verify Email", recipients=[user.email])
    msg.body = f"Click to verify: {link}"
    mail.send(msg)

    return "Check email to verify account"
@app.route('/verify/<token>')
def verify_email(token):
    email = serializer.loads(token, salt='email-verify', max_age=3600)
    user = User.query.filter_by(email=email).first()
    user.is_verified = True
    db.session.commit()
    return "Email verified successfully"
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        if not user.is_verified:
            return "Verify your email first"
        login_user(user)
        return redirect('/dashboard')

    return "Invalid credentials"
@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome {request.remote_user}"
@app.route('/admin')
@login_required
@role_required("admin")
def admin():
    return "Admin Dashboard"
@app.route('/reset', methods=['POST'])
def reset_password():
    email = request.form['email']
    token = serializer.dumps(email, salt='reset-password')

    link = url_for('reset_token', token=token, _external=True)
    msg = Message("Reset Password", recipients=[email])
    msg.body = link
    mail.send(msg)

    return "Password reset email sent"

@app.route('/reset/<token>', methods=['POST'])
def reset_token(token):
    email = serializer.loads(token, salt='reset-password', max_age=1800)
    user = User.query.filter_by(email=email).first()
    user.password = generate_password_hash(request.form['password'])
    db.session.commit()
    return "Password updated"
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')
@app.errorhandler(403)
def forbidden(e):
    return "Access denied", 403
