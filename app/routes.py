from flask import Blueprint, abort, app, jsonify, render_template, request, redirect, url_for, flash, session, current_app, g
from flask_login import current_user, logout_user, login_required, login_user
from . import db, mail
from .models import Notification, ProfileComment, RoommateProfile, User, Admin, SwapRequest, Announcement, RoomReport, AdminActivity, Warning, DisputeReports, CommentReport, StudentReport
from .utils import (get_admin_notifications, create_notification, get_user_notifications, is_valid_mmu_email, is_logged_in, is_admin_logged_in, send_room_owner_approval_request, send_swap_approved_email, send_swap_completion_email, send_swap_rejected_email, send_account_banned_email, send_account_warned_email, send_account_unbanned_email, send_swap_rejection_confirmation, send_swap_rejection_email,
                   setup_user_session, setup_admin_session, generate_token,
                   send_email, send_2fa_email,
                   send_verification_email)
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from math import ceil
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, or_

main = Blueprint('main', __name__)

def to_myt(utc_dt):
    myt = timezone(timedelta(hours=8))
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(myt)

@main.route('/')
def index():
    announcements = Announcement.query.order_by(Announcement.date_posted.desc()).limit(99).all()
    return render_template('index.html', 
                        logged_in=is_logged_in(),
                        admin_logged_in=is_admin_logged_in(),
                        announcements=announcements)

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
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Email verified successfully! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    else:
        # Try to find a user who is already verified (token may have been used)
        user = User.query.filter_by(is_verified=True).filter_by(verification_token=None).first()
        if user:
            flash('Email already verified. You can now log in.', 'success')
        else:
            flash('Invalid or expired verification link', 'error')
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
        
        if user.is_deleted:
            flash('Your account has been deleted. Please contact support.', 'error')
            return redirect(url_for('main.login'))
        if user.is_banned:
            flash(f'Your account has been banned. Reason: {user.ban_reason}.  Please contact support.', 'error')
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
    remember = session.get('remember_me', False)  
    setup_user_session(user, remember)
    session.pop('temp_2fa', None)
    session.pop('temp_user_id', None)
    session.pop('remember_me', None)
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
    user_id = session.get('user_id')
    swap_requests = SwapRequest.query.filter_by(user_id=user_id, is_deleted=False).all()
    # Convert UTC to MYT for display
    for request in swap_requests:
        request.local_timestamp = to_myt(request.date)
    return render_template('dashboard.html', logged_in=True, requests=swap_requests)

@main.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('main.index')) 

#Notification system
@main.route('/notification')
def notification():
    if not (is_logged_in() or is_admin_logged_in()):
        return redirect(url_for('main.login'))
        
    if is_logged_in():
        user_id = session['user_id']
        notifications = get_user_notifications(user_id)
    else:  # is admin
        admin_id = session['admin_id']
        notifications = get_admin_notifications(admin_id)
        
    return render_template('notification.html', notifications=notifications, is_logged_in=is_logged_in(), is_admin_logged_in=is_admin_logged_in())

@main.route('/mark-as-read/<int:notification_id>', methods=['POST'])
def mark_notification_as_read(notification_id):
    notification = Notification.query.get(notification_id)
    if notification:
        notification.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Notification not found"})

@main.route('/delete-notification/<int:notification_id>', methods=['POST'])
def delete_notification(notification_id):
    # Check if logged in as USER or ADMIN
    if is_logged_in():
        user_id = session.get('user_id')
        notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
    elif is_admin_logged_in():
        admin_id = session.get('admin_id')
        notification = Notification.query.filter_by(id=notification_id, admin_id=admin_id).first()
    else:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    if not notification:
        return jsonify({'success': False, 'message': 'Notification not found'}), 404

    db.session.delete(notification)
    db.session.commit()
    return jsonify({'success': True})


@main.route('/notification-count')
def notification_count():
    if is_logged_in():
        user_id = session.get('user_id')
        count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        return jsonify({'count': count})
    elif is_admin_logged_in():
        admin_id = session.get('admin_id')
        count = Notification.query.filter_by(admin_id=admin_id, is_read=False).count()
        return jsonify({'count': count})
    else:
        return jsonify({'count': 0})


#ADMIN ROUTES
@main.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    # Get admin ID from session
    admin_id = session.get('admin_id')
    admin = Admin.query.get_or_404(admin_id)

    total_requests = SwapRequest.query.filter_by(is_deleted=False).count()
    total_students = User.query.filter_by(is_deleted=False).count()
    pending_requests = SwapRequest.query.filter(SwapRequest.status == 'pending', SwapRequest.is_deleted == False).count()
    approved_requests = SwapRequest.query.filter(SwapRequest.status == 'approved', SwapRequest.is_deleted == False).count()
    rejected_requests = SwapRequest.query.filter(SwapRequest.status == 'rejected', SwapRequest.is_deleted == False).count()
    recent_requests = SwapRequest.query.filter_by(is_deleted=False).order_by(SwapRequest.date.desc()).limit(5).all()
    announcements = Announcement.query.order_by(Announcement.date_posted.desc()).all()

    for r in recent_requests:
        r.local_timestamp = to_myt(r.date)
    return render_template('admin_dashboard.html', total_requests=total_requests, total_students=total_students, pending_requests=pending_requests,
                            approved_requests=approved_requests, rejected_requests=rejected_requests, recent_requests=recent_requests,
                            announcements=announcements, admin=admin, logged_in=is_admin_logged_in())

@main.route('/admin/registered_admins')
def registered_admins():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    #GET query parameters
    search = request.args.get('search', '').lower()
    sort = request.args.get('sort', '')
    page = int(request.args.get('page', 1))
    per_page = 50
    
    admins = Admin.query
    #searching
    if search:
        admins = admins.filter(
            or_(func.lower(Admin.username).like(f"%{search}%"), 
                func.lower(Admin.admin_name).like(f"%{search}%")
                )
        )
    #sorting
    if sort == 'date_new':
        admins = admins.order_by(Admin.created_at.desc())
    elif sort == 'date_old':
        admins = admins.order_by(Admin.created_at.asc())
    else:
        admins = admins.order_by(Admin.created_at.desc())
    #pagination
    total = admins.count()
    total_pages = (total + per_page - 1) // per_page
    admins = admins.offset((page - 1) * per_page).limit(per_page).all()

    # Get total registered admins
    total_admins = Admin.query.count()
    # Convert UTC to MYT for display
    for admin in admins:
        admin.local_timestamp = to_myt(admin.created_at)

    return render_template('admins.html', admins=admins, logged_in=is_admin_logged_in(), total_admins=total_admins, 
                           search=search, sort=sort, page=page, total_pages=total_pages)

@main.route('/admin/requests')
def swap_requests():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    # GET query parameters
    search = request.args.get('search', '').lower()
    status = request.args.get('status', 'all')
    sort = request.args.get('sort', '')
    page = int(request.args.get('page', 1))
    per_page = 50

    query = SwapRequest.query.join(User, SwapRequest.user_id == User.id ).filter(SwapRequest.is_deleted == False )
    #searching
    if search:
        query = query.filter(func.lower(User.fullname).like(f"%{search}%"))
    #filtering by status
    if status != 'all':
        query = query.filter(SwapRequest.status==status)
    #sorting 
    if sort == 'name_asc':
        query = query.order_by(User.fullname.asc())
    elif sort == 'name_desc':
        query = query.order_by(User.fullname.desc())
    elif sort == 'date_new':
        query = query.order_by(SwapRequest.date.desc())
    elif sort == 'date_old':
        query = query.order_by(SwapRequest.date.asc())
    else:
        query = query.order_by(SwapRequest.date.desc())
    #pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    requests = query.offset((page - 1) * per_page).limit(per_page).all()

    # Convert UTC to MYT for display
    for r in requests:
        r.local_timestamp = to_myt(r.date)
        

    return render_template(
        'admin_requests.html',
        requests=requests,
        search=search,
        status=status,
        sort=sort,
        page=page,
        total_pages=total_pages
    )

@main.route('/admin/approve', methods=['POST'])
def approve_request():
    request_id = request.form.get('id')
    swap = SwapRequest.query.get(request_id)
    if swap:
        # Check if room owner has agreed to proceed
        if swap.room_owner_response != "approved":
            flash('Room owner has not agreed to proceed with this request yet', 'error')
            return redirect(request.referrer)
        
        # Set status to pending_owner_approval and send final confirmation email
        swap.status = "pending_owner_approval"

        timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
        admin_id= session.get('admin_id')
        admin = Admin.query.get_or_404(admin_id)
        activity = AdminActivity(
            admin_id=admin_id,
            action='approved',
            entity_type='Swap Request',
            entity_id=swap.id,
            details=(f"Swap request was approved by { admin.username } for {swap.user.fullname} (ID: {swap.user.student_id}) on {timestamp}\n\n"
                     f"Current Hostel: {swap.current_hostel}  | Desired Hostel: {swap.desired_hostel}\n"
                     f"Current Block:  {swap.current_block}  | Desired Block: {swap.desired_block}\n"
                     f"Current Room:   {swap.current_room}  | Desired Room:  {swap.desired_room}\n"
                     )
        )
        db.session.add(activity)

        db.session.commit()
        
        # Send final confirmation email to room owner
        from .utils import send_room_owner_approval_request
        room_owner = User.query.get(swap.room_owner_id)
        send_room_owner_approval_request(room_owner, swap)
        
        # Notify both users
        create_notification(
            user_id=swap.user.id,
            message=f"Your swap request has been approved by admin. Waiting for the room owner's final confirmation.",
            notification_type='swap_waiting_final'
        )
        create_notification(
            user_id=swap.room_owner.id,
            message=f"Admin has approved the swap request. Please check your email for the final confirmation.",
            notification_type='swap_final_confirmation'
        )
        
        flash('Swap approved by admin. Waiting for room owner final confirmation.', 'success')
    return redirect(request.referrer or url_for('main.swap_requests'))

@main.route('/room-owner-agreement/<token>', methods=['GET', 'POST'])
def room_owner_agreement(token):
    swap = SwapRequest.query.filter_by(room_owner_token=token).first()
    if not swap:
        flash('Invalid or expired link', 'error')
        return redirect(url_for('main.index'))

    # Prevent duplicate or automatic processing
    if swap.status != "pending_agreement":
        flash("This swap request has already been processed.", "warning")
        return render_template('swap_response.html', swap=swap, logged_in=is_logged_in(), admin_logged_in=is_admin_logged_in())

    if request.method == 'POST':
        response = request.form.get('response')
        if response == 'approve':
            # Update status to pending admin approval
            swap.status = "pending"
            swap.room_owner_response = "approved"
            swap.room_owner_response_at = datetime.utcnow()
            db.session.commit()
            
            # Notify admins
            admins = Admin.query.all()
            for admin in admins:
                create_notification(
                    admin_id=admin.id,
                    message=f"New swap request from Student ID: {swap.user.student_id}",
                    notification_type='new_request'
                )
            
            # Notify requester
            create_notification(
                user_id=swap.user_id,
                message=f"Your swap request has been approved by the room owner. Waiting for admin approval.",
                notification_type='swap_waiting'
            )
            
            # Render a waiting for admin approval message
            return render_template('swap_response.html', swap=swap, waiting_for_admin=True, logged_in=is_logged_in(), admin_logged_in=is_admin_logged_in())
        else:
            # Reject the swap request
            swap.status = "rejected"
            swap.room_owner_response = "rejected"
            swap.room_owner_response_at = datetime.utcnow()
            db.session.commit()
            
            # Notify requester
            send_swap_rejection_email(swap.user, swap)
            create_notification(
                user_id=swap.user_id,
                message=f"Your swap request has been rejected by the room owner.",
                notification_type='swap_rejected'
            )
            
            flash('Swap request rejected.', 'info')
            return render_template('swap_response.html', swap=swap, logged_in=is_logged_in(), admin_logged_in=is_admin_logged_in())

    # GET: Show confirmation page
    return render_template('room_owner_agreement.html', swap=swap, logged_in=is_logged_in(), admin_logged_in=is_admin_logged_in())

@main.route('/room-owner-response/<token>', methods=['GET', 'POST'])
def room_owner_response(token):
    swap = SwapRequest.query.filter_by(room_owner_token=token).first()
    if not swap:
        flash('Invalid or expired link', 'error')
        return redirect(url_for('main.index'))

    # Prevent duplicate or automatic processing
    if swap.status != "pending_owner_approval":
        flash("This swap request has already been processed.", "warning")
        return render_template('swap_response.html', swap=swap, logged_in=is_logged_in(), admin_logged_in=is_admin_logged_in())

    if request.method == 'POST':
        response = request.form.get('response')
        if response == 'approve':
            return complete_swap(swap)
        else:
            return reject_swap(swap)

    # GET: Show confirmation page
    return render_template('room_owner_confirm.html', swap=swap, logged_in=is_logged_in(), admin_logged_in=is_admin_logged_in())

def complete_swap(swap):
    # Get both users
    user = User.query.get(swap.user_id)
    room_owner = User.query.get(swap.room_owner_id)
    
    # Store original rooms for notification
    original_requester_room = f"{user.hostel}-{user.block}-{user.room}"
    original_owner_room = f"{room_owner.hostel}-{room_owner.block}-{room_owner.room}"
    
    # Swap the rooms
    user.hostel, room_owner.hostel = room_owner.hostel, user.hostel
    user.block, room_owner.block = room_owner.block, user.block
    user.room, room_owner.room = room_owner.room, user.room
    
    # Update swap status
    swap.status = "approved"
    swap.room_owner_response = "approved"
    swap.room_owner_response_at = datetime.utcnow()
    
    db.session.commit()
    
    # Notify both parties
    send_swap_completion_email(user, original_requester_room, f"{user.hostel}-{user.block}-{user.room}")
    send_swap_completion_email(room_owner, original_owner_room, f"{room_owner.hostel}-{room_owner.block}-{room_owner.room}")

    create_notification(
        user_id=swap.user.id,
        message=f"Your swap to {swap.desired_hostel}-{swap.desired_block}-{swap.desired_room} was approved!",
        notification_type='swap_approved'
    )
    
    create_notification(
        user_id=swap.room_owner.id,
        message=f"Swap complete. Your new room is now located at: ({swap.current_hostel}-{swap.current_block}-{swap.current_room})",
        notification_type='room_reassigned'
    )
    
    # Admin notification
    admins = Admin.query.all()
    for admin in admins:
        create_notification(
        admin_id=admin.id,  # Assuming admin is current_user
        message=f"Swap completed between {swap.user.fullname} and {swap.room_owner.fullname}",
        notification_type='admin_swap_approved'
    )
    
    flash('Room swap completed successfully!', 'success')
    return render_template('swap_response.html', swap=swap)
    

def update_map_visuals(swap):
    """Triggers updates for both rooms involved in the swap"""
    rooms_to_update = [
        {
            'hostel': swap.current_hostel,
            'block': swap.current_block,
            'room': swap.current_room,
            'new_occupant': swap.room_owner.fullname if swap.room_owner else "Vacant"
        },
        {
            'hostel': swap.desired_hostel,
            'block': swap.desired_block,
            'room': swap.desired_room,
            'new_occupant': swap.requester.fullname
        }
    ]



def reject_swap(swap):
    swap.status = "rejected"
    swap.room_owner_response = "rejected"
    swap.room_owner_response_at = datetime.utcnow()
    db.session.commit()
    
    # Notify BOTH parties
    requester = User.query.get(swap.user_id)
    room_owner = User.query.get(swap.room_owner_id)
    
    # Send to requester
    send_swap_rejection_email(requester, swap)
    
    # Send to room owner
    send_swap_rejection_confirmation(room_owner, swap)
    
    create_notification(
        user_id=swap.user.id,
        message=f"Your swap to {swap.desired_hostel}-{swap.desired_block}-{swap.desired_room} was rejected.",
        notification_type='swap_approved'
    )
    
    create_notification(
        user_id=swap.room_owner.id,
        message=f"You have declined the room swap request. No changes have been made.",
        notification_type='room_reassigned'
    )
    
    # Admin notification
    admins = Admin.query.all()
    for admin in admins:
        create_notification(
        admin_id=admin.id,  # Assuming admin is current_user
        message=f"Swap requested between {swap.user.fullname} and {swap.room_owner.fullname} was rejected.",
        notification_type='admin_swap_approved'
    )
    return render_template('swap_response.html', swap=swap)



@main.route('/admin/reject', methods=['POST'])
def reject_request():
    request_id = request.form.get('id')
    swap = SwapRequest.query.get(request_id)
    if swap:
        swap.status = "rejected"

        timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
        admin_id = session.get('admin_id')
        admin = Admin.query.get_or_404(admin_id)
        activity = AdminActivity(
            admin_id=admin_id,
            action='rejected',
            entity_type='Swap Request',
            entity_id=swap.id,
            details=(f"Swap request was rejected by { admin.username } for {swap.user.fullname} (ID: {swap.user.student_id}) on {timestamp}\n\n"
                     f"Current Hostel: {swap.current_hostel}  | Desired Hostel: {swap.desired_hostel}\n"
                     f"Current Block:  {swap.current_block}  | Desired Block: {swap.desired_block}\n"
                     f"Current Room:   {swap.current_room}  | Desired Room:  {swap.desired_room}\n"
                     
                     )
        )
        db.session.add(activity)
        db.session.commit()

        user = User.query.get(swap.user_id)
    
    # Send simple text email
    try:
        send_swap_rejected_email(user, swap)
    except Exception as e:
        app.logger.error(f"Email sending failed: {str(e)}")
        flash('Rejected but failed to send email', 'warning')
        
    # Notify the user
    create_notification(
        user_id=swap.user_id,
        message=f"Your swap request to {swap.desired_hostel} (Block {swap.desired_block}, Room {swap.desired_room}) has been rejected.",
        notification_type='swap_rejected'
        )
    flash('Request rejected!', 'success')
    return redirect(request.referrer or url_for('main.swap_requests'))

@main.route('/admin/request/delete', methods=['POST'])
def delete_request_admin():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    request_id = request.form.get('id')
    swap = SwapRequest.query.get_or_404(request_id)

    if swap.is_deleted:
        flash('Request already deleted', 'error')
        return redirect(request.referrer or url_for('main.swap_requests'))
    
    admin_id = session.get('admin_id')
    admin = Admin.query.get_or_404(admin_id)

    swap.is_deleted = True
    swap.deleted_at = datetime.utcnow()
    swap.deleted_by_admin_id = admin_id

    timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
    activity = AdminActivity(
        admin_id=admin_id,
        action='deleted',
        entity_type='Swap Request',
        entity_id=swap.id,
        
        details=(f"Record was deleted by { admin.username } for {swap.user.fullname} (ID: {swap.user.student_id}) on {timestamp}\n\n"
                 f"Deleted Data:\n"
                 f"Current Hostel: {swap.current_hostel}  | Desired Hostel: {swap.desired_hostel}\n"
                 f"Current Block:  {swap.current_block}  | Desired Block: {swap.desired_block}\n"
                 f"Current Room:   {swap.current_room}  | Desired Room:  {swap.desired_room}\n"
                 f"Status: {swap.status}\n"
                 f"Date: {swap.date}\n")
    )
        
    db.session.add(activity)

    db.session.commit()
    flash('Request deleted successfully!', 'success')
    return redirect(request.referrer or url_for('main.swap_requests'))

@main.route('/admin/students')
def admin_students():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    
    
    # GET query parameters
    search = request.args.get('search', '').lower()
    hostel = request.args.get('hostel', 'all')
    block = request.args.get('block', 'all')
    page = int(request.args.get('page', 1))
    per_page = 50
    query = User.query.filter_by(is_deleted=False)

    #searching
    if search:
        query = query.filter(func.lower(User.fullname).like(f"%{search}%"))
    #filtering by hostel
    if hostel != 'all':
        query = query.filter(User.hostel==hostel)
    #filtering by block
    if block != 'all':
        query = query.filter(User.block==block)
    #pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    students = query.offset((page - 1) * per_page).limit(per_page).all()
    
    
   
    return render_template('admin_students.html', students=students , search=search, hostel=hostel, block=block,
                           page=page,total_pages=total_pages)

@main.route('/admin/student/delete', methods=['POST'])
def delete_student_admin():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    student_id = request.form.get('id')
    student = User.query.get_or_404(student_id)

    if student.is_deleted:
        flash('Student already deleted', 'error')
        return redirect(request.referrer or url_for('main.admin_students'))
    
    admin_id = session.get('admin_id')
    admin = Admin.query.get_or_404(admin_id)

    student.is_deleted = True
    student.deleted_at = datetime.utcnow()
    student.deleted_by_admin_id = admin_id

    
    
    timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
    activity = AdminActivity(
        admin_id=admin_id,
        action='deleted',
        entity_type='Student',
        entity_id=student.id,
        details=(f"Record was deleted by { admin.username } for {student.fullname} (ID: {student.student_id}) on {timestamp}\n\n"
                 f"Deleted Data:\n"
                 f"Student ID: {student.student_id}\n"
                 f"Name: {student.fullname}\n"
                 f"Email: {student.email}\n"
                 f"Hostel: {student.hostel}  | Block: {student.block} | Room: {student.room}\n"
                 )
                 
        
    )  
    db.session.add(activity)
    db.session.commit()
    flash('Student data is deleted successfully!', 'success')
        
    return redirect(request.referrer or url_for('main.admin_students'))




@main.route('/admin/student/edit/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    student = User.query.get_or_404(student_id)
    #update user details
    if request.method == 'POST':
        admin_id = session.get('admin_id')
        admin = Admin.query.get_or_404(admin_id)

        old_hostel = student.hostel
        old_block = student.block
        old_room = student.room

        new_hostel = request.form.get('hostel')
        new_block = request.form.get('block')
        new_room = request.form.get('room')

        student.hostel = new_hostel
        student.block = new_block
        student.room = new_room

        if old_hostel != new_hostel or old_block != new_block or old_room != new_room:
            timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
            activity = AdminActivity(
                admin_id=admin_id,
                action='edited',
                entity_type='Student',
                entity_id=student.id,
                details=(f"Record was updated by { admin.username } for {student.fullname} (ID: {student.student_id}) on {timestamp}\n\n"
                         f"Changes:\n"
                         f"Hostel: {old_hostel} -> {new_hostel}\n"
                         f"Block: {old_block} -> {new_block}\n" 
                         f"Room: {old_room} -> {new_room}\n"
                     )
                )
            db.session.add(activity)
        db.session.commit()
        flash("Student details are updated successfully!", "success")
        return redirect(url_for('main.edit_student', student_id=student.id)) 

    return render_template('edit_student.html', student=student) 

@main.route('/admin/student_profile/<int:student_id>')
def view_student_profile(student_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    student = User.query.get_or_404(student_id)
    swap_requests = SwapRequest.query.filter_by(user_id=student.id).all()
    warnings = Warning.query.filter_by(user_id=student.id).order_by(Warning.date_issued.desc()).all()

    # Convert UTC to MYT for display
    for s in swap_requests:
        s.local_timestamp = to_myt(s.date)
    
    
    return render_template('admin_view_student.html', student=student, swap_requests=swap_requests, warnings=warnings )

@main.before_app_request
def check_if_banned():
    if 'user_id' in session:
        # Define safe endpoints to skip ban checking
        safe_endpoints = ['main.login', 'main.logout', 'main.register','main.index', 'static']

        if request.endpoint in safe_endpoints:
            return

        user = User.query.get(session['user_id'])
        if user and user.is_banned:
            flash(f'Your account has been banned. Reason: {user.ban_reason}. Please contact support.', 'error')
            logout_user()
            return redirect(url_for('main.login'))

@main.route('/admin/ban_student/<int:student_id>', methods=['POST'])
def ban_student(student_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    student = User.query.get_or_404(student_id)
    ban_reason = request.form.get('ban_reason')
    
    if not ban_reason:
        flash('Ban reason is required', 'error')
        return redirect(request.referrer or url_for('main.admin_students'))

    student.is_banned = True
    student.ban_reason = ban_reason

    timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
    admin_id = session.get('admin_id')
    admin = Admin.query.get_or_404(admin_id)
    activity = AdminActivity(
        admin_id=admin_id,
        action='banned',
        entity_type='Student',
        entity_id=student.id,
        details=(f"Student was banned by { admin.username } for {student.fullname} (ID: {student.student_id}) on {timestamp}\n\n"
                 f"Ban Reason: {ban_reason}\n"
                 f"Hostel: {student.hostel}  | Block: {student.block} | Room: {student.room}\n"
                 )
    )
    db.session.add(activity)
    db.session.commit()

    #send simple text email to student
    try:
        send_account_banned_email(student)
            
    except Exception as e:
        app.logger.error(f"Failed to send ban email: {str(e)}")
        flash('Student banned but failed to send email notification', 'warning')
    
    
    flash('Student banned successfully!', 'success')
    return redirect(request.referrer or url_for('main.admin_students'))

@main.route('/admin/unban_student/<int:student_id>', methods=['POST'])
def unban_student(student_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    student = User.query.get_or_404(student_id)
    student.is_banned = False
    student.ban_reason = None

    timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
    admin_id = session.get('admin_id')
    admin = Admin.query.get_or_404(admin_id)
    activity = AdminActivity(
        admin_id=admin_id,
        action='unbanned',
        entity_type='Student',
        entity_id=student.id,
        details=(f"Student was unbanned by { admin.username } for {student.fullname} (ID: {student.student_id}) on {timestamp}\n\n"
                 f"Hostel: {student.hostel}  | Block: {student.block} | Room: {student.room}\n"
                 )
    )
    db.session.add(activity)

    db.session.commit()

    #send simple text email to student
    try:
        send_account_unbanned_email(student)

    except Exception as e:
        app.logger.error(f"Failed to send unban email: {str(e)}")
        flash('Student unbanned but failed to send email notification', 'warning')
    
    flash('Student unbanned successfully!', 'success')
    return redirect(request.referrer or url_for('main.admin_students'))

@main.route('/admin/warning_student/<int:student_id>', methods=['POST'])
def warn_student(student_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    student = User.query.get_or_404(student_id)

    if student.is_banned:
        flash('Cannot warn a banned student.', 'error')
        return redirect(request.referrer or url_for('main.admin_students'))
    
    

    warn_reason = request.form.get('warn_reason')
    if not warn_reason:
        flash('Warning reason is required.', 'error')
        return redirect(request.referrer or url_for('main.admin_students'))

    try:
        student.warning_count = (student.warning_count or 0) + 1
        db.session.commit()

        # Save warning reason to Warning table
        admin_id = session.get('admin_id')
        warning = Warning(user_id=student.id, reason=warn_reason, admin_id=admin_id)
        db.session.add(warning)
        db.session.commit()

        send_account_warned_email(student, warn_reason)
        # Create notification for the student
        create_notification(
            user_id=student.id,
            message=f"You have been warned by an admin. Reason: {warn_reason}",
            notification_type='warning'
        )
        flash(f'{student.fullname} has been warned successfully!', 'success')

    except Exception as e:
            current_app.logger.error(f"Failed to warn student: {str(e)}")
            flash('An error occurred while warning the student.', 'error')
    
    

    return redirect(request.referrer or url_for('main.admin_students'))

@main.route('/admin/dispute_reports')
def dispute_reports():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    query = DisputeReports.query

    total_reports = query.count()
    pending_reports = query.filter(DisputeReports.status == 'Pending').count()
    resolved_reports = query.filter(DisputeReports.status == 'resolved').count()


    # GET query parameters
    status = request.args.get('status', 'all')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    page = int(request.args.get('page', 1))
    per_page = 50

    
    #filtering by status
    if status != 'all':
        query = query.filter(DisputeReports.status==status)
    #filtering by date range
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d")
            query = query.filter(DisputeReports.date >= from_dt)
        except ValueError:
            pass

    if to_date:
        try:
            to_dt = datetime.strptime(to_date, "%Y-%m-%d")
            to_dt = to_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(DisputeReports.date <= to_dt)
        except ValueError:
            pass
    
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    query = query.order_by(DisputeReports.date.desc())

    reports = query.offset((page - 1) * per_page).limit(per_page).all()

    for r in reports:
        r.local_timestamp = to_myt(r.date)
        
    return render_template('admin_reports.html', total_reports=total_reports, pending_reports=pending_reports, resolved_reports=resolved_reports, reports=reports,logged_in=is_admin_logged_in(),
                            status=status, from_date=from_date, to_date=to_date,
                            page=page, total_pages=total_pages)

@main.route('/report/resolve/<int:report_id>', methods=['POST'])
def resolve_report(report_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))

    report = DisputeReports.query.get_or_404(report_id)
    report.status = 'resolved'
    db.session.commit()

    # Notify the user who reported
    create_notification(
        user_id=report.user_id,
        message=f"Your report against {report.reported_student} has been resolved.",
        notification_type='report_resolved'
    )

    flash('Report resolved successfully!', 'success')
    return redirect(request.referrer or url_for('main.dispute_reports'))

@main.route('/report/dismiss/<int:report_id>', methods=['POST'])
def dismiss_report(report_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))

    report = DisputeReports.query.get_or_404(report_id)
    report.status = 'dismissed'
    db.session.commit()

    # Notify the user who reported
    create_notification(
        user_id=report.user_id,
        message=f"Your report against {report.reported_student} has been dismissed.",
        notification_type='report_dismissed'
    )

    flash('Report dismissed successfully!', 'success')
    return redirect(request.referrer or url_for('main.dispute_reports'))

@main.route('/report-comment/<int:reported_student_id>/<int:profile_id>', methods=['GET', 'POST'])
def report_comment(reported_student_id, profile_id):
    if not is_logged_in():
        flash('Please login to report a comment', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        reason = request.form.get('reason')
        description = request.form.get('description')

        if not reason or not description:
            flash('Reason and description are required', 'error')
            return redirect(request.referrer or url_for('main.report_comment', reported_student_id=reported_student_id, profile_id=profile_id))

        reporter_id = session.get('user_id')
        reported_student = User.query.get_or_404(reported_student_id)
        reporter = User.query.get_or_404(reporter_id)

        report = CommentReport(
            reporter_id=reporter_id,
            reported_student_id=reported_student.id,
            reason=reason,
            description=description
        )
        db.session.add(report)

        # Create a dispute report entry
        send_report = DisputeReports(
            user_id=reporter_id,
            reported_student=reported_student.fullname,
            reported_by=reporter.fullname,
            reason=reason,
            description=description,
            status='Pending'
        )
        db.session.add(send_report)

        
        db.session.commit()
        

        # Create notification for the admins
        admins = Admin.query.all()
        for admin in admins:
            create_notification(
                admin_id=admin.id,
                message=f"New comment report from {reporter.fullname} (ID: {reporter.student_id}) against {reported_student.fullname} (ID: {reported_student.student_id}).",
                notification_type='comment_report'
            )
            
        flash('Comment reported successfully!', 'success')

        return redirect(url_for('main.view_profiles', user_id=profile_id))

    return render_template('comment_report.html', reported_student_id=reported_student_id)

@main.route('/report-student/<int:reported_student_id>', methods=['GET', 'POST'])
def report_student(reported_student_id):
    if not is_logged_in():
        flash('Please login to report a student', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        reason = request.form.get('reason')
        description = request.form.get('description')

        if not reason or not description:
            flash('Reason and description are required', 'error')
            return redirect(request.referrer or url_for('main.report_student', reported_student_id=reported_student_id))

        reporter_id = session.get('user_id')
        reported_student = User.query.get_or_404(reported_student_id)
        reporter = User.query.get_or_404(reporter_id)

        report = StudentReport(
            reporter_id=reporter_id,
            reported_student_id=reported_student.id,
            reason=reason,
            description=description
        )
        db.session.add(report)

        send_report = DisputeReports(
            user_id=reporter_id,
            reported_student=reported_student.fullname,
            reported_by=reporter.fullname,
            reason=reason,
            description=description,
            status='Pending'
        )
        db.session.add(send_report)
        db.session.commit()
        
        # Create notification for the admins
        admins = Admin.query.all()
        for admin in admins:
            create_notification(
                admin_id=admin.id,
                message=f"New student report from {reporter.fullname} (ID: {reporter.student_id}) against {reported_student.fullname} (ID: {reported_student.student_id}).",
                notification_type='student_report'
            )
            
        
        
        flash('Student reported successfully!', 'success')

        return redirect(url_for('main.incoming_requests'))

    return render_template('student_report.html', reported_student_id=reported_student_id)



    
@main.route('/incoming_requests')
@login_required
def incoming_requests():
    if not current_user.is_verified:
        flash('Please login to view incoming requests', 'error')
        return redirect(url_for('main.login'))

    #GET query parameters
    page= int(request.args.get('page', 1))
    per_page = 50

    # Only show requests where the current user is the room owner
    requests = (
        db.session.query(SwapRequest, User)
        .join(User, SwapRequest.user_id == User.id)
        .filter(SwapRequest.room_owner_id == current_user.id,
                SwapRequest.is_deleted == False,
                User.is_deleted == False,
                SwapRequest.status.in_(['pending_owner_approval', 'rejected', 'approved'])
        )
        .order_by(SwapRequest.date.desc())
        .all()
    )

    requests_data = []
    for swap_request, requester in requests:
        requests_data.append({
            'user_id': requester.id,
            'requester_name': requester.fullname,
            'requester_location': f"{swap_request.current_hostel}-{swap_request.current_block}-{swap_request.current_room}",
            'my_location': f"{swap_request.desired_hostel}-{swap_request.desired_block}-{swap_request.desired_room}",
            'requested_date': swap_request.date,
            'status': swap_request.status
        })  
    # Pagination
    total_requests = len(requests_data)
    total_pages = (total_requests + per_page - 1) // per_page
    requests_data = requests_data[(page - 1) * per_page: page * per_page]

    # Convert UTC to MYT for display
    for req in requests_data:
        req['local_timestamp'] = to_myt(req['requested_date'])

    

    return render_template('incoming_requests.html', requests=requests_data, logged_in=is_logged_in(),page=page, total_pages=total_pages)



@main.route('/submit', methods=['GET', 'POST'])
def submit_request():
    if not is_logged_in():
        flash('Please login first', 'error')
        return redirect(url_for('main.login'))
    
    user = User.query.get(current_user.id)
    current_location = {
        'hostel': user.hostel,
        'block': user.block,
        'room': user.room
    }
    
    if request.method == 'POST':
        desired_hostel = request.form.get('desired_hostel')
        desired_block = request.form.get('desired_block')
        desired_room = request.form.get('desired_room')
        
        # Check if room exists and has an occupant
        room_owner = User.query.filter_by(
            hostel=desired_hostel,
            block=desired_block,
            room=desired_room,
            is_deleted=False
        ).first()
        
        if not room_owner:
            flash('No occupant found in the requested room', 'error')
            return redirect(url_for('main.submit_request'))
            
        # Create new swap request
        new_swap = SwapRequest(
            user_id=user.id,
            current_hostel=user.hostel,
            current_block=user.block,
            current_room=user.room,
            desired_hostel=desired_hostel,
            desired_block=desired_block,
            desired_room=desired_room,
            status="pending_agreement",
            room_owner_id=room_owner.id
        )

        try:
            db.session.add(new_swap)
            db.session.commit()
            
            # Generate token for room owner approval
            token = generate_token()
            new_swap.room_owner_token = token
            db.session.commit()
            
            # Send email to room owner for initial agreement
            response_url = url_for('main.room_owner_agreement', token=token, _external=True)
            body = f"""Dear {room_owner.fullname},

A student has requested to swap rooms with you:

Current Location: {user.hostel} - Block {user.block}, Room {user.room}
Desired Location: {desired_hostel} - Block {desired_block}, Room {desired_room}

Please review this request and respond:
[Review Swap Request] {response_url}

If you accept, the request will be sent to admin for final approval.
If you reject, the request will be automatically rejected.

Best regards,
Tukar-Je Support Team
"""
            send_email('Room Swap Request - Action Required', room_owner.email, body)
            
            # Create notification for the user
            create_notification(
                user_id=user.id,
                message=f"Your swap request to {desired_hostel}-{desired_block}-{desired_room} has been submitted successfully.",
                notification_type='swap_request'
            )
            
            # Create notification for room owner
            create_notification(
                user_id=room_owner.id,
                message=f"You have received a room swap request. Please check your email to respond.",
                notification_type='swap_request'
            )
            
            flash('Swap request submitted successfully!', 'success')
            return redirect(url_for('main.submit_request'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error submitting swap request: {str(e)}")
            flash('An error occurred while submitting your request. Please try again.', 'error')
            return redirect(url_for('main.submit_request'))

    return render_template('submit_form.html', 
                         current_location=current_location,
                         logged_in=is_logged_in(),
                         admin_logged_in=is_admin_logged_in())

@main.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        admin_name = request.form.get('admin_name')
        username = request.form.get('username')
        password = request.form.get('password')
        secret_key = request.form.get('secret_key')
        
        if secret_key != current_app.config['ADMIN_SECRET_KEY']:
            flash('Invalid secret key', 'error')
            return redirect(url_for('main.admin_register'))
            
        if Admin.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('main.admin_register'))
            
        admin = Admin(
            admin_name=admin_name,
            username=username,
            password=generate_password_hash(password)
        )
        
        db.session.add(admin)
        db.session.commit()
        
        flash('Admin account created successfully', 'success')
        return redirect(url_for('main.admin_login'))
        
    return render_template('admin_register.html')

@main.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            setup_admin_session(admin, remember)
            return redirect(url_for('main.admin_dashboard'))
            
        flash('Invalid username or password', 'error')
        return redirect(url_for('main.admin_login'))
        
    return render_template('admin_login.html')

@main.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('main.index'))

# History and status
@main.route('/edit-request/<int:request_id>', methods=['GET', 'POST'])
def edit_request(request_id):
    swap_request = SwapRequest.query.get_or_404(request_id)

    if request.method == 'POST':
        # Update fields from form data
        swap_request.desired_hostel = request.form.get('desired_hostel')
        swap_request.desired_block = request.form.get('desired_block')
        swap_request.desired_room = request.form.get('desired_room')
        
        db.session.commit()
        return redirect(url_for('main.dashboard'))

    return render_template('edit_request.html', swap_request=swap_request)

@main.route('/delete_request/<int:request_id>', methods=['GET'])
def delete_request(request_id):
    req = SwapRequest.query.get_or_404(request_id)
    db.session.delete(req)
    db.session.commit()
    flash("Deleted successfully!", "success")
    return redirect(url_for('main.dashboard'))

# Hostel Map
@main.route('/map')
def hostel_map():
    if not (is_logged_in() or is_admin_logged_in()):
        return redirect(url_for('main.login'))
    hostel = request.args.get('hostel', 'HB1')
    block = request.args.get('block', 'A')
    floor = request.args.get('floor', 'Ground Floor')
    return render_template('map.html', logged_in=is_logged_in(), hostel=hostel, block=block, floor=floor, 
                           admin_logged_in=is_admin_logged_in())

@main.route('/admin/room/edit_occupants', methods=['GET'])
def edit_room_occupants():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    hostel = request.args.get('hostel')
    block = request.args.get('block')
    room = request.args.get('room')

    current_occupants = User.query.filter_by(hostel=hostel, block=block, room=room, is_deleted=False).all()

    return render_template('admin_edit_room.html', 
                           hostel=hostel, block=block, room=room, 
                           current_occupants=current_occupants, 
                           admin_logged_in=is_admin_logged_in())

@main.route('/admin/room/add_occupant', methods=['POST'])
def add_room_occupant():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    student_id = request.form.get('student_id')
    hostel = request.form.get('hostel')
    block = request.form.get('block')
    room = request.form.get('room')

    current_occupants = User.query.filter_by(hostel=hostel, block=block, room=room, is_deleted=False).count()
    if current_occupants >= 2:
        flash('Room is already full', 'error')
        return redirect(url_for('main.edit_room_occupants', hostel=hostel, block=block, room=room))

    student = User.query.filter_by(student_id=student_id, is_deleted=False).first()
    if student:
        if student.hostel != 'Unassigned' and student.block != 'Unassigned' and student.room != 'Unassigned':
            flash(f'Student {student.fullname} was moved from {student.hostel}-{student.block}-{student.room} to {hostel}-{block}-{room}.', 'warning')
        student.hostel = hostel
        student.block = block
        student.room = room

        timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
        admin_id = session.get('admin_id')
        admin = Admin.query.get_or_404(admin_id)

        activity = AdminActivity(
            admin_id=admin_id,
            action='edited',
            entity_type='Room Occupant',
            entity_id=student.id,
            details=(f"{student.fullname} (ID: {student.student_id}) was added to {hostel}-{block}-{room} by {admin.username} on {timestamp}\n\n")
        )
        db.session.add(activity)
        

        db.session.commit()
        # Create notification for the student
        create_notification(
            user_id=student.id,
            message=f"You have been assigned to {hostel}-{block}-{room} by an admin.",
            notification_type='room_assignment'
        )
        flash(f'Student {student.fullname} added to {hostel}-{block}-{room} successfully!', 'success')
    else:
        flash('Student not found', 'error')
    return redirect(url_for('main.edit_room_occupants', hostel=hostel, block=block, room=room,))

@main.route('/admin/room/remove_occupant', methods=['POST'])
def remove_room_occupant():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    student_id = request.form.get('student_id')
    hostel = request.form.get('hostel')
    block = request.form.get('block')
    room = request.form.get('room')

    student = User.query.filter_by(student_id=student_id, hostel=hostel, block=block, room=room, is_deleted=False).first()
    
    if student and student.hostel == hostel and student.block == block and student.room == room:
        student.hostel = 'Unassigned'
        student.block = 'Unassigned'
        student.room = 'Unassigned'

        timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
        admin_id = session.get('admin_id')
        admin = Admin.query.get_or_404(admin_id)
        activity = AdminActivity(
            admin_id=admin_id,
            action='edited',
            entity_type='Room Occupant',
            entity_id=student.id,
            details=(f"{student.fullname} (ID: {student.student_id}) was removed from {hostel}-{block}-{room} by {admin.username} on {timestamp}\n\n")
        )
        db.session.add(activity)

        db.session.commit()
        flash(f'{student.fullname} removed from {hostel}-{block}-{room} successfully!', 'success')
    
    #add to activity log
    
    
    return redirect(url_for('main.edit_room_occupants', hostel=hostel, block=block, room=room))

@main.route('/admin/announcement/add', methods=['POST'])
def add_announcement():
    if not is_admin_logged_in():
        flash('Unauthorized', 'error')
        return redirect(url_for('main.admin_dashboard'))
    content = request.form.get('content')
    if not content:
        flash('Announcement content required', 'error')
        return redirect(url_for('main.admin_announcements'))
    admin_id = session.get('admin_id')
    ann = Announcement(content=content, admin_id=admin_id)
    db.session.add(ann)
    db.session.commit()
    flash('Announcement posted!', 'success')
    return redirect(url_for('main.admin_announcements'))

@main.route('/admin/announcement/edit/<int:id>', methods=['POST'])
def edit_announcement(id):
    if not is_admin_logged_in():
        flash('Unauthorized', 'error')
        return redirect(url_for('main.admin_dashboard'))
    ann = Announcement.query.get_or_404(id)
    new_content = request.form.get('content')
    if new_content:
        ann.content = new_content
        db.session.commit()
        flash('Announcement updated!', 'success')
    else:
        flash('Content cannot be empty.', 'error')
    return redirect(url_for('main.admin_announcements'))

@main.route('/admin/announcement/delete/<int:id>', methods=['POST'])
def delete_announcement(id):
    if not is_admin_logged_in():
        flash('Unauthorized', 'error')
        return redirect(url_for('main.admin_dashboard'))
    ann = Announcement.query.get_or_404(id)
    db.session.delete(ann)
    db.session.commit()
    flash('Announcement deleted!', 'success')
    return redirect(url_for('main.admin_announcements'))

@main.route('/admin/announcements')
def admin_announcements():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    announcements = Announcement.query.order_by(Announcement.date_posted.desc()).all()
    edit_id = request.args.get('edit_id', type=int)
    return render_template('admin_announcements.html', announcements=announcements, edit_id=edit_id)

# Roommate
@main.route('/roommate', methods=['GET', 'POST'])
def roommate():
    if not is_logged_in():
        return redirect(url_for('main.login'))
    
    user = User.query.get(session['user_id'])
    profile = RoommateProfile.query.filter_by(user_id=user.id).first()

    if request.method == 'POST':
        # Validate year input
        try:
            year = int(request.form.get('year'))
            if year not in [1, 2, 3]:
                flash('Please select a valid year of study', 'error')
                return redirect(url_for('main.roommate'))
        except (ValueError, TypeError):
            flash('Invalid year of study selected', 'error')
            return redirect(url_for('main.roommate'))

        # Profile data 
        profile_data = {
            'gender': request.form.get('gender'),
            'course_level': request.form.get('course'),  
            'faculty': request.form.get('faculty'),
            'year': year,
            'about': request.form.get('about'),
            'contact_method': request.form.get('contact_method'),
            'contact_info': request.form.get('contact_info')
        }

        # Validate required fields
        required_fields = ['gender', 'course_level', 'faculty', 'contact_method', 'contact_info']
        for field in required_fields:
            if not profile_data[field]:
                flash(f'{field.replace("_", " ").title()} is required', 'error')
                return redirect(url_for('main.roommate'))

        # Create or update profile
        if profile:
            for key, value in profile_data.items():
                setattr(profile, key, value)
        else:
            profile = RoommateProfile(user_id=user.id, **profile_data)
            db.session.add(profile)
        
        try:
            db.session.commit()
            flash('Profile saved successfully!', 'success')
            return redirect(url_for('main.roommate'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving your profile', 'error')
            return redirect(url_for('main.roommate'))

    return render_template('roommate.html', profile=profile, logged_in=True)

@main.route('/roommate/profiles')
def view_profiles():
    if not is_logged_in():
        return redirect(url_for('main.login'))
    
    gender_filter = request.args.get('gender')
    course_filter = request.args.get('course_level')  
    faculty_filter = request.args.get('faculty')
    year_filter = request.args.get('year')

    query = RoommateProfile.query.join(User)
    
    if gender_filter:
        query = query.filter(RoommateProfile.gender == gender_filter)
    if course_filter:
        query = query.filter(RoommateProfile.course_level.ilike(f"%{course_filter}%"))
    if faculty_filter:
        query = query.filter(RoommateProfile.faculty == faculty_filter)
    if year_filter:
        query = query.filter(RoommateProfile.year == year_filter)

    profiles = query.all()
    requests = SwapRequest.query.all()
    return render_template('profiles.html', 
                         profiles=profiles, 
                         requests=requests, 
                         logged_in=True)

# To delete personal roommate profile
@main.route('/delete_profile/<int:profile_id>', methods=['GET'])
def delete_profile(profile_id):
    if not is_logged_in():
        return redirect(url_for('main.login'))

    profile = RoommateProfile.query.get_or_404(profile_id)
     # Delete all comments on this profile
    ProfileComment.query.filter_by(profile_id=profile.user_id).delete()
    
    db.session.delete(profile)
    db.session.commit()
    flash("Your profile has been deleted successfully.", "success")
    return redirect(url_for('main.view_profiles'))


@main.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def view_profile(user_id):
    profile_user = User.query.get_or_404(user_id)

    if not is_logged_in():
        return redirect(url_for('main.login'))

    comments = ProfileComment.query.filter_by(
        profile_id=user_id,
        is_deleted=False
    ).order_by(ProfileComment.timestamp.asc()).all()

    myt = timezone(timedelta(hours=8))
    for comment in comments:
        comment.local_timestamp = comment.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)
    
    return render_template(
        'profiles.html',
        profile=profile_user,
        comments=comments,
        is_logged_in=is_logged_in
    )



@main.route('/profile/<int:user_id>/modal')
def profile_modal(user_id):
    profile = RoommateProfile.query.filter_by(user_id=user_id).first_or_404()
    return render_template('profile_partial.html', profile=profile)

@main.route('/profile/comments/<int:user_id>')
def profile_comments(user_id):
    comments = ProfileComment.query.filter_by(
        profile_id=user_id,
        is_deleted=False,
        parent_id=None  # Only fetch top-level comments
    ).order_by(ProfileComment.timestamp.desc()).all()

    myt = timezone(timedelta(hours=8))
    for comment in comments:
        comment.local_timestamp = comment.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)
        # Set local_timestamp for replies too
        comment.replies = [r for r in comment.replies if not r.is_deleted]
        for reply in comment.replies:
            reply.local_timestamp = reply.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)

    profile = User.query.get_or_404(user_id)

    return render_template('comment_partial.html', profile=profile, comments=comments, is_logged_in=is_logged_in())

@main.route('/add_comment_modal/<int:user_id>', methods=['POST'])
def add_comment_modal(user_id):
    # Check if request is AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
              request.accept_mimetypes.accept_json
    
    if not is_ajax:
        if request.form:  # If form data was submitted
            return "This endpoint requires AJAX", 400
        abort(400, description="This endpoint only accepts AJAX requests")
    
    # Check authentication
    if 'user_id' not in session:
        return "Please log in to comment", 401
    
    try:
        # Create new comment
        new_comment = ProfileComment(
            profile_id=user_id,
            author_id=session['user_id'],
            content=content
        )
        db.session.add(new_comment)
        
        # Create notification if commenting on someone else's profile
        if user_id != session['user_id']:
            create_notification(
                user_id=user_id,
                message=f"You received a new comment from {current_user.fullname}",
                notification_type='new_comment'
            )
            
        db.session.commit()
        
        # Return updated comments section
        comments = ProfileComment.query.filter_by(
            profile_id=user_id,
            is_deleted=False
        ).order_by(ProfileComment.timestamp.desc()).all()
        
        # Apply timezone conversion
        myt = timezone(timedelta(hours=8))
        for comment in comments:
            comment.local_timestamp = comment.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)
            # Set local_timestamp for replies too
            comment.replies = [r for r in comment.replies if not r.is_deleted]
            for reply in comment.replies:
                reply.local_timestamp = reply.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)

        content = request.form.get('comment', '').strip()
        
        return render_template('comment_partial.html', 
            profile=User.query.get(user_id),
            comments=comments,
            is_logged_in=True
        )
        
    except Exception as e:
        db.session.rollback()
        return f"Error posting comment: {str(e)}", 500
    
@main.route('/handle_comment', methods=['POST'])
def handle_comment():
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Please log in to comment'}), 401

    try:
        user_id = request.form.get('user_id')
        content = request.form.get('comment', '').strip()
        parent_id = request.form.get('parent_id')

        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user ID'}), 400
        if not content:
            return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400
        if len(content) > 1000:
            return jsonify({'success': False, 'error': 'Comment too long (max 1000 characters)'}), 400

        parent_comment = None
        if parent_id:
            parent_id = int(parent_id)
            parent_comment = ProfileComment.query.get(parent_id)
            if not parent_comment or parent_comment.is_deleted:
                return jsonify({'success': False, 'error': 'Invalid parent comment'}), 400
        else:
            parent_id = None

        # Get the current user from the session
        author = User.query.get(session['user_id'])
        if not author:
            return jsonify({'success': False, 'error': 'User not found'}), 400

        new_comment = ProfileComment(
            profile_id=int(user_id),
            author_id=session['user_id'],
            content=content,
            parent_id=parent_id
        )
        db.session.add(new_comment)

        # Create notification if commenting on someone else's profile
        if int(user_id) != session['user_id']:
            notification_msg = f"You received a new {'reply' if parent_id else 'comment'} from {author.fullname}"
            create_notification(
                user_id=int(user_id),
                message=notification_msg,
                notification_type='new_comment'
            )

        db.session.commit()

        comments = ProfileComment.query.filter_by(
            profile_id=int(user_id),
            is_deleted=False,
            parent_id=None
        ).order_by(ProfileComment.timestamp.desc()).all()

        myt = timezone(timedelta(hours=8))
        for comment in comments:
            comment.local_timestamp = comment.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)
            # Set local_timestamp for replies too
            comment.replies = [r for r in comment.replies if not r.is_deleted]
            for reply in comment.replies:
                reply.local_timestamp = reply.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)

        return render_template('comment_partial.html',
                               profile=User.query.get(int(user_id)),
                               comments=comments,
                               is_logged_in=True)

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error handling comment: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@main.route('/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    comment = ProfileComment.query.get_or_404(comment_id)

    # Check if the current user is the author
    if comment.author_id != session.get('user_id'):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'You are not authorized to delete this comment.'}), 401
        flash('You are not authorized to delete this comment.', 'error')
        return redirect(url_for('main.view_profiles'))

    # Soft delete implementation
    comment.is_deleted = True
    comment.deleted_at = datetime.utcnow()
    comment.deleted_by = session.get('user_id')
    
    db.session.commit()
    
    # Return updated comments section for both AJAX and non-AJAX requests
    comments = ProfileComment.query.filter_by(
        profile_id=comment.profile_id,
        is_deleted=False
    ).order_by(ProfileComment.timestamp.asc()).all()
    
    # Apply timezone conversion
    myt = timezone(timedelta(hours=8))
    for c in comments:
        c.local_timestamp = c.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('comment_partial.html', 
            profile=User.query.get(comment.profile_id),
            comments=comments,
            is_logged_in=True
        )
    
    # For non-AJAX requests, redirect back to profiles page
    flash('Comment deleted.', 'success')
    return redirect(url_for('main.view_profiles'))


    
# Report Room Issues
@main.route('/room-report', methods=['GET', 'POST'])
def room_report():
    if not is_logged_in():
        flash('Please login to submit a room report', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        issue_type = request.form.get('issue_type')
        description = request.form.get('description')
        priority = request.form.get('priority')

        new_report = RoomReport(
            user_id=user.id,
            hostel=user.hostel,
            block=user.block,
            room=user.room,
            issue_type=issue_type,
            description=description,
            priority=priority
        )

        try:
            db.session.add(new_report)
            db.session.commit()

            # Notify all admins
            admins = Admin.query.all()
            for admin in admins:
                create_notification(
                    admin_id=admin.id,
                    message=f"New room report from {user.fullname} ({user.hostel}-{user.block}-{user.room})",
                    notification_type='room_report'
                )

            flash('Room report submitted successfully!', 'success')
            return redirect(url_for('main.room_report'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your report. Please try again.', 'error')
            return redirect(url_for('main.room_report'))

    return render_template('room_report.html', 
                         user=user,
                         logged_in=is_logged_in(),
                         admin_logged_in=is_admin_logged_in())

@main.route('/my-reports')
def my_reports():
    if not is_logged_in():
        flash('Please login to view your reports', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.login'))

    # Get query parameters
    status = request.args.get('status', 'all')
    page = int(request.args.get('page', 1))
    per_page = 10

    query = RoomReport.query.filter_by(user_id=user.id)

    # Filtering by status
    if status != 'all':
        query = query.filter(RoomReport.status == status)

    # Sorting by date (newest first)
    query = query.order_by(RoomReport.date_reported.desc())

    # Pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    reports = query.offset((page - 1) * per_page).limit(per_page).all()

    return render_template('my_reports.html',
                         reports=reports,
                         status=status,
                         page=page,
                         total_pages=total_pages,
                         user=user,
                         logged_in=is_logged_in(),
                         admin_logged_in=is_admin_logged_in())

@main.route('/admin/room-reports')
def admin_room_reports():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))

    # Get query parameters
    search = request.args.get('search', '').lower()
    status = request.args.get('status', 'all')
    priority = request.args.get('priority', 'all')
    page = int(request.args.get('page', 1))
    per_page = 50

    query = RoomReport.query

    # Searching
    if search:
        query = query.join(User).filter(
            (func.lower(User.fullname).like(f"%{search}%")) |
            (func.lower(RoomReport.description).like(f"%{search}%"))
        )

    # Filtering by status
    if status != 'all':
        query = query.filter(RoomReport.status == status)

    # Filtering by priority
    if priority != 'all':
        query = query.filter(RoomReport.priority == priority)

    # Sorting by date (newest first)
    query = query.order_by(RoomReport.date_reported.desc())

    # Pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    reports = query.offset((page - 1) * per_page).limit(per_page).all()

    return render_template('admin_room_reports.html',
                         reports=reports,
                         search=search,
                         status=status,
                         priority=priority,
                         page=page,
                         total_pages=total_pages)

@main.route('/admin/room-report/<int:report_id>', methods=['GET', 'POST'])
def admin_room_report_detail(report_id):
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))

    report = RoomReport.query.get_or_404(report_id)

    if request.method == 'POST':
        status = request.form.get('status')
        admin_notes = request.form.get('admin_notes')

        report.status = status
        report.admin_notes = admin_notes
        report.admin_id = session.get('admin_id')

        if status == 'resolved':
            report.date_resolved = datetime.utcnow()
            # Notify the user
            create_notification(
                user_id=report.user_id,
                message=f"Your room report for {report.hostel}-{report.block}-{report.room} has been resolved.",
                notification_type='report_resolved'
            )

        if status == 'in_progress':
            create_notification(
                user_id=report.user_id,
                message=f"Your room report for {report.hostel}-{report.block}-{report.room} is now in progress.",
                notification_type='report_in_progress'
            )

        db.session.commit()
        flash('Report updated successfully!', 'success')
        return redirect(url_for('main.admin_room_report_detail', report_id=report.id))

    return render_template('admin_room_report_detail.html', report=report)

@main.route('/mark-report-resolved/<int:report_id>', methods=['POST'])
def mark_report_resolved(report_id):
    if not is_logged_in():
        flash('Please login to perform this action', 'error')
        return redirect(url_for('main.login'))

    report = RoomReport.query.get_or_404(report_id)
    user = User.query.get(session['user_id'])
    if report.user_id != user.id:
        flash('You are not authorized to update this report.', 'error')
        return redirect(url_for('main.my_reports'))

    if report.status != 'in_progress':
        flash('Only reports that are in progress can be marked as resolved.', 'error')
        return redirect(url_for('main.my_reports'))

    report.status = 'resolved'
    report.date_resolved = datetime.utcnow()
    db.session.commit()

    # Notify all admins
    admins = Admin.query.all()
    for admin in admins:
        create_notification(
            admin_id=admin.id,
            message=f"User {user.fullname} marked their room report for {report.hostel}-{report.block}-{report.room} as resolved.",
            notification_type='user_resolved_report'
        )

    flash('Report marked as resolved. Thank you for confirming!', 'success')
    return redirect(url_for('main.my_reports'))
@main.route('/admin/activitylog')
def admin_activitylog():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    
    
    # GET query parameters
    search = request.args.get('search', '').lower()
    action = request.args.get('action', 'all')
    entity = request.args.get('entity', 'all')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    page = int(request.args.get('page', 1))
    per_page = 50

    query = AdminActivity.query
    #searching
    if search:
        query = query.filter(
            func.lower(AdminActivity.details).like(f"%{search}%")
        )
    #filtering by action
    if action != 'all':
        query = query.filter(AdminActivity.action==action)
    #filtering by entity
    if entity != 'all':
        query = query.filter(AdminActivity.entity_type==entity)
    #filtering by date range
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d")
            query = query.filter(AdminActivity.timestamp >= from_dt)
        except ValueError:
            pass

    if to_date:
        try:
            to_dt = datetime.strptime(to_date, "%Y-%m-%d")
            to_dt = to_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(AdminActivity.timestamp <= to_dt)
        except ValueError:
            pass
    #pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    query = query.order_by(AdminActivity.timestamp.desc())
    activities = query.offset((page - 1) * per_page).limit(per_page).all()
    
    for a in activities:
        a.local_timestamp = to_myt(a.timestamp)
        
    
    return render_template('admin_activity.html', activities=activities, search=search, action=action, entity=entity,
                            from_date=from_date, to_date=to_date,page=page, total_pages=total_pages,  )

@main.route('/admin/request/restore', methods=['POST'])
def restore_request_admin():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))

    request_id = request.form.get('id')
    swap = SwapRequest.query.get_or_404(request_id)

    if not swap.is_deleted:
        flash('Request is not deleted', 'warning')
        return redirect(request.referrer or url_for('main.swap_requests'))

    admin_id = session.get('admin_id')
    admin= Admin.query.get_or_404(admin_id)
    

    # Restore the swap request
    swap.is_deleted = False
    swap.deleted_at = None
    swap.deleted_by_admin_id = None

    timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
    activity = AdminActivity(
        admin_id=admin_id,
        action='restored',
        entity_type='Swap Request',
        entity_id=swap.id,
        details=(f"Record was restored by { admin.username } for {swap.user.fullname} (ID: {swap.user.student_id}) on {timestamp}\n\n"
                 f"Restored Data:\n"
                 f"Current Hostel: {swap.current_hostel}  | Desired Hostel: {swap.desired_hostel}\n"
                 f"Current Block:  {swap.current_block}  | Desired Block: {swap.desired_block}\n"
                 f"Current Room:   {swap.current_room}  | Desired Room:  {swap.desired_room}\n"
                 f"Status: {swap.status}\n"
                 f"Date: {swap.date}\n")
            )
    db.session.add(activity)
    db.session.commit()
    flash('Request restored successfully!', 'success')
    return redirect(request.referrer or url_for('main.swap_requests'))

@main.route('/admin/student/restore', methods=['POST'])
def restore_student_admin():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))

    student_id = request.form.get('id')
    student = User.query.get_or_404(student_id)

    if not student.is_deleted:
        flash('Student data is not deleted', 'warning')
        return redirect(request.referrer or url_for('main.admin_students'))

    admin_id = session.get('admin_id')
    admin= Admin.query.get_or_404(admin_id)
    

    # Restore the student data
    student.is_deleted = False
    student.deleted_at = None
    student.deleted_by_admin_id = None

    timestamp = to_myt(datetime.utcnow()).strftime('%B %d, %Y, %I:%M %p')
    activity = AdminActivity(
        admin_id=admin_id,
        action='restored',
        entity_type='Student',
        entity_id=student.id,
        details=(f"Record was restored by { admin.username } for {student.fullname} (ID: {student.student_id}) on {timestamp}\n\n"
                 f"Restored Data:\n"
                 f"Student ID: {student.student_id}\n"
                 f"Name: {student.fullname}\n"
                 f"Email: {student.email}\n"
                 f"Hostel: {student.hostel}  | Block: {student.block} | Room: {student.room}\n"
                 )  
            )  
    db.session.add(activity)
    db.session.commit()
    flash('Student data is restored successfully!', 'success')
    return redirect(request.referrer or url_for('main.admin_students'))


@main.route('/settings', methods=['GET', 'POST'])
def settings():
    if not is_logged_in():
        flash('Please log in to access settings', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('main.settings'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('main.settings'))

        # Update password
        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password updated successfully', 'success')
        return redirect(url_for('main.settings'))

    return render_template('settings.html', user=user)

@main.route('/settings/profile')
def settings_profile():
    if not is_logged_in():
        flash('Please log in to access settings', 'error')
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.login'))
    return render_template('settings_profile.html', user=user, active_tab='profile')

@main.route('/settings/room')
def settings_room():
    if not is_logged_in():
        flash('Please log in to access settings', 'error')
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.login'))
    return render_template('settings_room.html', user=user, active_tab='room')

@main.route('/admin/settings/profile')
def admin_settings_profile():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    admin = Admin.query.get(session['admin_id'])
    if not admin:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.admin_login'))
    return render_template('admin_settings_profile.html', admin=admin, active_tab='profile')

@main.route('/admin/settings/account', methods=['GET', 'POST'])
def admin_settings_account():
    if not is_admin_logged_in():
        flash('Please login as admin', 'error')
        return redirect(url_for('main.admin_login'))
    admin = Admin.query.get(session['admin_id'])
    if not admin:
        session.clear()
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.admin_login'))
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not check_password_hash(admin.password, current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('main.admin_settings_account'))
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('main.admin_settings_account'))
        admin.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully', 'success')
        return redirect(url_for('main.admin_settings_account'))
    return render_template('admin_settings_account.html', admin=admin, active_tab='account')

@main.route('/room/<hostel>/<block>/<room>')
def room_info(hostel, block, room):
    # Query the database for all users registered to this room
    occupants = User.query.filter_by(
        hostel=hostel,
        block=block,
        room=room
    ).all()
    
    return render_template('room_info.html',
                         hostel=hostel,
                         block=block,
                         room=room,
                         occupants=occupants,
                         logged_in=is_logged_in(),
                         admin_logged_in=is_admin_logged_in())

