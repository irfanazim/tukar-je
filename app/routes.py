from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from . import db, mail
from .models import User
from .utils import (is_valid_mmu_email, is_logged_in, generate_token, 
                   setup_user_session, send_email, send_2fa_email,
                   send_verification_email)
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html', logged_in=is_logged_in())

@main.route('/register', methods=['GET', 'POST'])
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


        if not is_valid_mmu_email(form_data['email']):
            flash('Please use a valid MMU student email address', 'error')
            return redirect(url_for('main.register'))

        if User.query.filter_by(email=form_data['email']).first():
            flash('Email already registered', 'error')
            return redirect(url_for('main.register'))

        if User.query.filter_by(student_id=form_data['student_id']).first():
            flash('Student ID already registered', 'error')
            return redirect(url_for('main.register'))

        user = User(
            fullname=form_data['fullname'],
            email=form_data['email'],
            student_id=form_data['student_id'],
            password=generate_password_hash(form_data['password']),
            hostel=form_data['hostel'],
            block=form_data['block'],
            room=form_data['room'],
        )

        try:
            db.session.add(user)

            if send_verification_email(user):
                flash('Registration successful! Please check your email to verify your account.', 'success')
                return redirect(url_for('main.login'))
            else:
                flash('Registration successful, but failed to send verification email. Please contact support.', 'warning')
                return redirect(url_for('main.login'))

        except Exception as e:
            db.session.rollback()
            print(f"Error during user registration: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('main.register'))

    return render_template('register.html')

@main.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        flash('Invalid or expired verification link', 'error')
        return redirect(url_for('main.login'))
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('main.login'))

        if not user.is_verified:
            flash('Please verify your email before logging in', 'error')
            return redirect(url_for('main.login'))

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

@main.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'temp_2fa' not in session or 'temp_user_id' not in session:
        return redirect(url_for('main.login'))

    entered_code = request.form.get('2fa_code')
    if entered_code != session['temp_2fa']:
        return redirect(url_for('main.login'))

    user = User.query.get(session['temp_user_id'])
    setup_user_session(user, session.get('remember_me', False))
    return redirect(url_for('main.dashboard'))

@main.route('/forgot-password', methods=['GET', 'POST'])
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

        reset_url = url_for('main.reset_password', token=reset_token, _external=True)
        body = f'''To reset your password, visit the following link:
{reset_url}'''

        try:
            send_email('Reset Your Password - Tukar-Je', email, body)
            flash('Password reset link sent! Please check your email.', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            print(f"Error sending reset email: {str(e)}")
            flash('Error sending email. Please try again.', 'error')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash('Invalid or expired reset link', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash('Password is required', 'error')
            return render_template('reset_password.html')

        user.password = generate_password_hash(password)
        user.reset_token = None
        db.session.commit()

        flash('Password changed successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('main.login'))

    return render_template('reset_password.html')

@main.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('main.login'))
    return render_template('dashboard.html', logged_in=True)

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index')) 