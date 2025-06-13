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

def send_account_banned_email(student):
    body = f'''Dear {student.fullname},

Your account has been banned due to violation of our terms of service. 
Please note that you will not be able to log in or access your account.

If you believe this is a mistake, please contact support.

If you have any questions, please reply to this email.

Best regards,
Tukar-Je Support Team
'''
    send_email('Account Banned', student.email, body)

def send_account_unbanned_email(student):
    body = f'''Dear {student.fullname},

Your account has been unbanned and you can now log in again.
Please ensure you follow our terms of service to avoid future issues.
Your account is now active and you can access all features.

If you have any questions, please reply to this email.

Best regards,
Tukar-Je Support Team
'''
    send_email('Account Unbanned', student.email, body)

def send_account_warned_email(student, warn_reason):
    body = f'''Dear {student.fullname},
    
You have received a warning for violating our terms of service.
Reason: {warn_reason}
Your warning count is now {student.warning_count}.

If you continue to violate our terms, further actions may be taken.
If you have any questions, please reply to this email.

Best regards,
Tukar-Je Support Team
'''
    send_email('Account Warning', student.email, body)

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



def send_room_owner_approval_request(room_owner, swap_request):
    token = generate_token()
    swap_request.room_owner_token = token
    db.session.commit()
    
    approve_url = url_for('main.room_owner_response', token=token, response='approve', _external=True)
    reject_url = url_for('main.room_owner_response', token=token, response='reject', _external=True)
    
    body = f"""Dear {room_owner.fullname},

A room swap request has been approved for your current room:
- Current Room: {swap_request.desired_hostel}-{swap_request.desired_block}-{swap_request.desired_room}
- Proposed Room: {swap_request.current_hostel}-{swap_request.current_block}-{swap_request.current_room}

ACTION REQUIRED (respond within 3 days):
[APPROVE SWAP]({approve_url})
[REJECT SWAP]({reject_url})

If approved, this swap will be processed immediately.

Best regards,
Tukar-Je Support Team
"""
    send_email(
        subject="Action Required: Room Swap Approval", 
        recipient=room_owner.email, 
        body=body
    )


def send_consent_email(room_owner, requester, swap_request):
    """Initial consent request before admin review"""
    approve_url = url_for('main.owner_consent', token=swap_request.consent_token, response='approve', _external=True)
    reject_url = url_for('main.owner_consent', token=swap_request.consent_token, response='reject', _external=True)
    
    body = f"""Dear {room_owner.fullname},

{requester.fullname} has requested to swap rooms with you:
- Your Current Room: {swap_request.desired_hostel}-{swap_request.desired_block}-{swap_request.desired_room}
- Their Current Room: {requester.hostel}-{requester.block}-{requester.room}

PLEASE CONSENT:
[AGREE TO SWAP]({approve_url})
[DECLINE REQUEST]({reject_url})

Note: Your consent is required before admin review.

Best regards,
Tukar-Je Support Team
"""
    send_email(
        subject="Room Swap Consent Request", 
        recipient=room_owner.email, 
        body=body
    )


def send_final_approval_email(room_owner, swap):
    """Final confirmation after admin approval"""
    approve_url = url_for('main.final_owner_approval', token=swap.room_owner_token, response='approve', _external=True)
    reject_url = url_for('main.final_owner_approval', token=swap.room_owner_token, response='reject', _external=True)
    
    body = f"""Dear {room_owner.fullname},

FINAL CONFIRMATION REQUIRED:

The administrator has approved your room swap:
- Your Current Room: {swap.desired_hostel}-{swap.desired_block}-{swap.desired_room}
- New Room Assignment: {swap.current_hostel}-{swap.current_block}-{swap.current_room}

[CONFIRM SWAP]({approve_url})
[CANCEL REQUEST]({reject_url})

This is your final opportunity to confirm this swap.

Best regards,
Tukar-Je Support Team
"""
    send_email(
        subject="Final Confirmation Required", 
        recipient=room_owner.email, 
        body=body
    )


def send_swap_completion_email(user, old_room, new_room):
    """Notification when swap is successfully completed"""
    body = f"""Dear {user.fullname},

ROOM SWAP COMPLETED:
- Previous Room: {old_room}
- New Room: {new_room}

Please collect your new room key from the hostel office.

Best regards,
Tukar-Je Support Team
"""
    send_email(
        subject="Room Swap Completed", 
        recipient=user.email, 
        body=body
    )


def send_swap_rejection_email(user, swap):
    """Notification when swap is rejected by room owner"""
    body = f"""Dear {user.fullname},

Your swap request has been declined:
- Requested Room: {swap.desired_hostel}-{swap.desired_block}-{swap.desired_room}

You may submit a new request for a different room.

Best regards,
Tukar-Je Support Team
"""
    send_email(
        subject="Swap Request Declined", 
        recipient=user.email, 
        body=body
    )


def send_swap_rejection_confirmation(room_owner, swap):
    """Confirmation to room owner who rejected request"""
    body = f"""Dear {room_owner.fullname},

You have successfully declined the swap request for:
- Room: {swap.desired_hostel}-{swap.desired_block}-{swap.desired_room}

The requester has been notified.

Best regards,
Tukar-Je Support Team
"""
    send_email(
        subject="Swap Declined Confirmation", 
        recipient=room_owner.email, 
        body=body
    )

def send_swap_rejected_email(user, swap):
    body = f"""Dear {user.fullname},

We regret to inform you that your room swap request has been rejected by the administrator, despite the room owner's consent.

Request Details:
- Requested Room: {swap.desired_hostel} - Block {swap.desired_block}, Room {swap.desired_room}

You may submit a new request for a different room if desired.

Best regards,
Tukar-Je Support Team
"""
    send_email('Room Swap Declined', user.email, body)

def send_admin_rejection_to_owner(room_owner, swap):
    body = f"""Dear {room_owner.fullname},

Thank you for consenting to the recent room swap request involving your room:
- Room: {swap.desired_hostel} - Block {swap.desired_block}, Room {swap.desired_room}
- Requested Room: {swap.current_hostel} - Block {swap.current_block}, Room {swap.current_room}

However, please note that the hostel administrator has decided to reject the request after review.

No further action is needed from your side. We appreciate your cooperation.

Best regards,  
Tukar-Je Support Team
"""
    send_email('Admin Rejected Swap Request', room_owner.email, body)