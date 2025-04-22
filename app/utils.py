from email_validator import validate_email, EmailNotValidError
import secrets
from datetime import timedelta
from flask import session, current_app
from flask_mail import Message
from . import mail

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
        current_app.permanent_session_lifetime = timedelta(days=30)
    else:
        current_app.permanent_session_lifetime = timedelta(hours=1)
    session['user_id'] = user.id
    session['user_email'] = user.email
    session['user_fullname'] = user.fullname

def send_email(subject, recipient, body):
    msg = Message(subject,
                 sender=('Tukar-Je Support', current_app.config['MAIL_USERNAME']),
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