from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tukar_je.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_DEBUG'] = True

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# Database 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    hostel = db.Column(db.String(10), nullable=False)
    block = db.Column(db.String(1), nullable=False)
    room = db.Column(db.String(10), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)

# Email validation function
def is_valid_mmu_email(email):
    try:
        # first validate the email format
        validate_email(email)
        # then check if its an mmu student email
        return email.endswith('@student.mmu.edu.my')
    except EmailNotValidError:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])  
def login():
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])  
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        return redirect(url_for('reset_password', token='dummy-token'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])  
def reset_password(token):
    return render_template('reset_password.html')

@app.route('/register', methods=['GET', 'POST'])  
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# http://localhost:5000/test-email/test@student.mmu.edu.my
# http://localhost:5000/test-email/test@gmail.com
@app.route('/test-email/<email>')
def test_email(email):
    is_valid = is_valid_mmu_email(email)
    return f"Email: {email}<br>Is valid MMU email: {is_valid}"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)