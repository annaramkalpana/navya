
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
