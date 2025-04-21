from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tukar_je.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

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

# Database Models
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

# Helper Functions
def is_valid_mmu_email(email):
    try:
        validate_email(email)
        return email.endswith('@student.mmu.edu.my')
    except EmailNotValidError:
        return False

def is_logged_in():
    return 'user_id' in session

def generate_token(length=32):
    return secrets.token_urlsafe(length)

def setup_user_session(user, remember=False):
    session.clear()
    session.permanent = True
    if remember:
        app.permanent_session_lifetime = timedelta(days=30)
    else:
        app.permanent_session_lifetime = timedelta(hours=1)
    session['user_id'] = user.id
    session['user_email'] = user.email
    session['user_fullname'] = user.fullname

def send_email(subject, recipient, body):
    msg = Message(subject,
                 sender=('Tukar-Je Support', app.config['MAIL_USERNAME']),
                 recipients=[recipient])
    msg.body = body
    mail.send(msg)

def send_2fa_email(user, twofa_code):
    body = f'''Dear {user.fullname},

Your Tukar-Je login verification code is: {twofa_code}

If you did not request this code, please ignore this email.

Best regards,
Tukar-Je Support Team
'''
    send_email('Your Tukar-Je Login Verification Code', user.email, body)

# Routes
@app.route('/')
def index():
    return render_template('index.html', logged_in=is_logged_in())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form_data = {
            'fullname': request.form.get('fullname'),
            'email': request.form.get('email'),
            'student_id': request.form.get('studentid'),
            'password': request.form.get('password'),
            'hostel': request.form.get('hostel'),
            'block': request.form.get('block'),
            'room': request.form.get('room')
        }

        # Check if any required field is missing
        for key, value in form_data.items():
            if not value:
                flash(f'{key.replace("_", " ").title()} is required', 'error')
                return redirect(url_for('register'))

        if not is_valid_mmu_email(form_data['email']):
            flash('Please use a valid MMU student email address', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=form_data['email']).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(student_id=form_data['student_id']).first():
            flash('Student ID already registered', 'error')
            return redirect(url_for('register'))

        verification_token = generate_token()
        user = User(
            fullname=form_data['fullname'],
            email=form_data['email'],
            student_id=form_data['student_id'],
            password=generate_password_hash(form_data['password']),
            hostel=form_data['hostel'],
            block=form_data['block'],
            room=form_data['room'],
            verification_token=verification_token
        )

        try:
            db.session.add(user)
            db.session.commit()

            verification_url = url_for('verify_email', token=verification_token, _external=True)
            body = f'''Please click the following link to verify your email:
{verification_url}'''

            send_email('Verify Your Email - Tukar-Je', form_data['email'], body)
            
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        flash('Invalid or expired verification link', 'error')
        return redirect(url_for('login'))
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('Please verify your email before logging in', 'error')
            return redirect(url_for('login'))

        twofa_code = ''.join(secrets.choice('0123456789') for _ in range(6))
        session['temp_2fa'] = twofa_code
        session['temp_user_id'] = user.id
        session['remember_me'] = remember

        try:
            send_2fa_email(user, twofa_code)
            return render_template('verify_2fa.html')
        except Exception as e:
            print(f"Error sending 2FA email: {str(e)}")
            return render_template('verify_2fa.html')

    return render_template('login.html')

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'temp_2fa' not in session or 'temp_user_id' not in session:
        return redirect(url_for('login'))

    entered_code = request.form.get('2fa_code')
    if entered_code != session['temp_2fa']:
        return redirect(url_for('login'))

    user = User.query.get(session['temp_user_id'])
    setup_user_session(user, session.get('remember_me', False))
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required', 'error')
            return render_template('forgot_password.html')
            
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found', 'error')
            return render_template('forgot_password.html')

        reset_token = generate_token()
        user.reset_token = reset_token
        db.session.commit()

        reset_url = url_for('reset_password', token=reset_token, _external=True)
        body = f'''To reset your password, visit the following link:
{reset_url}'''

        try:
            send_email('Reset Your Password - Tukar-Je', email, body)
            flash('Password reset link sent! Please check your email.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error sending reset email: {str(e)}")
            flash('Error sending email. Please try again.', 'error')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash('Invalid or expired reset link', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash('Password is required', 'error')
            return render_template('reset_password.html')

        user.password = generate_password_hash(password)
        user.reset_token = None
        db.session.commit()

        flash('Password changed successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('dashboard.html', logged_in=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 