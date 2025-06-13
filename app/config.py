import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # Basic configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///tukar_je.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds

    # Email configuration
    MAIL_SERVER = 'smtp.sendgrid.net'
    MAIL_PORT = 2525
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    MAIL_DEBUG = True

    # Admin configuration
    ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', 'your-default-admin-secret-key')