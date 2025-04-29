from email_validator import validate_email, EmailNotValidError
import secrets
from datetime import timedelta
from flask import session, current_app, url_for
from flask_mail import Message

from app.models import Notification
from . import mail, db

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

def send_verification_email(user):
    verification_token = generate_token()
    user.verification_token = verification_token
    try:
        db.session.add(user) 
        db.session.commit()

        verification_url = url_for('main.verify_email', token=verification_token, _external=True)
        subject = 'Verify Your Email - Tukar-Je'
        body = f'''Please click the following link to verify your email:
{verification_url}'''
        send_email(subject, user.email, body)
        return True 
    except Exception as e:
        print(f"Error sending verification email: {str(e)}")
        db.session.rollback()
        user.verification_token = None 
        return False 

# Notification system
def create_notification(message, notification_type, user_id=None, admin_id=None):
    notification = Notification(
        user_id=user_id,
        admin_id=admin_id,
        message=message,
        is_read=False,
        notification_type=notification_type
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def get_user_notifications(user_id):
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.timestamp.desc()).all()
    for n in notifications:
        n.timestamp = n.timestamp + timedelta(hours=8)  # Malaysia Time 
    return notifications

def get_admin_notifications(admin_id):
    notifications = Notification.query.filter_by(admin_id=admin_id).order_by(Notification.timestamp.desc()).all()
    for n in notifications:
        n.timestamp = n.timestamp + timedelta(hours=8)  # Malaysia Time 
    return notifications


def mark_notification_as_read(notification_id, user_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
    if notification:
        notification.is_read = True
        db.session.commit()
        return True
    return False

def send_swap_approved_email(user, swap):
    body = f'''Dear {user.fullname},

Your swap request has been approved!

Current Location: {swap.current_hostel} - Block {swap.current_block}, Room {swap.current_room}
New Location: {swap.desired_hostel} - Block {swap.desired_block}, Room {swap.desired_room}

Please contact your hostel office for further instructions.

Best regards,
Tukar-Je Support Team
'''
    send_email('Swap Request Approved', user.email, body)

def send_swap_rejected_email(user, swap):
    body = f'''Dear {user.fullname},

We regret to inform you that your swap request has been rejected.

Requested Location: {swap.desired_hostel} - Block {swap.desired_block}, Room {swap.desired_room}

If you have any questions, please reply to this email.

Best regards,
Tukar-Je Support Team
'''
    send_email('Swap Request Rejected', user.email, body)

# Admin Sessions
def is_admin_logged_in():
    return 'admin_id' in session

def setup_admin_session(admin, remember=False):
    session.clear()
    session.permanent = True
    if remember:
        current_app.permanent_session_lifetime = timedelta(days=30)
    else:
        current_app.permanent_session_lifetime = timedelta(hours=1)
    session['admin_id'] = admin.id
    session['admin_username'] = admin.username
    session['is_admin'] = True
