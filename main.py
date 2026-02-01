
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
