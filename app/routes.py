from flask import Blueprint, abort, app, jsonify, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import current_user
from . import db, mail
from .models import Notification, ProfileComment, RoommateProfile, User, Admin, SwapRequest, Announcement, RoomReport, AdminActivity
from .utils import (get_admin_notifications, create_notification, get_user_notifications, is_valid_mmu_email, is_logged_in, is_admin_logged_in, send_swap_approved_email, send_swap_rejected_email, 
                   setup_user_session, setup_admin_session, generate_token,
                   send_email, send_2fa_email,
                   send_verification_email)
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from math import ceil
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, or_

main = Blueprint('main', __name__)

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
        
        if user.is_deleted:
            flash('Your account has been deleted. Please contact support.', 'error')
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
    user_id = session.get('user_id')
    swap_requests = SwapRequest.query.filter_by(user_id=user_id, is_deleted=False).all()
    return render_template('dashboard.html', logged_in=True, requests=swap_requests)

@main.route('/logout')
def logout():
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

    query = SwapRequest.query.join(User).filter(SwapRequest.is_deleted == False)
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
        swap.status = "approved"
        db.session.commit()

        user = User.query.get(swap.user_id)
    
    # Send simple text email
    try:
        send_swap_approved_email(user, swap)
    except Exception as e:
        app.logger.error(f"Email sending failed: {str(e)}")
        flash('Approved but failed to send email', 'warning')
        
    # Notify the user
    create_notification(
        user_id=swap.user_id,
         message=f"Your swap request to {swap.desired_hostel} (Block {swap.desired_block}, Room {swap.desired_room}) has been approved!",
         notification_type='swap_approved'
        )
    flash('Request approved!', 'success')
    return redirect(request.referrer or url_for('main.swap_requests'))

@main.route('/admin/reject', methods=['POST'])
def reject_request():
    request_id = request.form.get('id')
    swap = SwapRequest.query.get(request_id)
    if swap:
        swap.status = "rejected"
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

    timestamp = datetime.utcnow().strftime('%B %d, %Y, %I:%M %p')
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

    
    
    timestamp = datetime.utcnow().strftime('%B %d, %Y, %I:%M %p')
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
            timestamp = datetime.utcnow().strftime('%B %d, %Y, %I:%M %p')
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


@main.route('/submit', methods=['GET', 'POST'])
def submit_request():
    if not is_logged_in():
        flash('Please login to submit a swap request', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()  # Clear invalid session
        flash('Your session has expired. Please login again.', 'error')
        return redirect(url_for('main.login'))
    current_location = {
        'hostel': user.hostel,
        'block': user.block,
        'room': user.room
    }

    if request.method == 'POST':
        desired_hostel = request.form.get('desired_hostel')
        desired_block = request.form.get('desired_block')
        desired_room = request.form.get('desired_room')
        
        print(f"Form data: desired_hostel={desired_hostel}, desired_block={desired_block}, desired_room={desired_room}")
        print(f"User data: id={user.id}, hostel={user.hostel}, block={user.block}, room={user.room}")

        # Create new swap request
        new_swap = SwapRequest(
            user_id=user.id,
            current_hostel=user.hostel,
            current_block=user.block,
            current_room=user.room,
            desired_hostel=desired_hostel,
            desired_block=desired_block,
            desired_room=desired_room,
            status="pending"
        )

        try:
            db.session.add(new_swap)
            db.session.commit()
            print("Swap request added successfully")
            
            # Create notification for the user
            create_notification(
                user_id=user.id,
                message=f"Your swap request to {desired_hostel}-{desired_block}-{desired_room} has been submitted successfully.",
                notification_type='swap_request'
            )
             # Notify all admins
            admins = Admin.query.all()
            for admin in admins:
                create_notification(
                    admin_id=admin.id,
                    message=f"New swap request from Student ID: {user.student_id}",
                    notification_type='new_request'
                    )
            
            flash('Swap request submitted successfully!', 'success')
            return redirect(url_for('main.submit_request'))
        except Exception as e:
            db.session.rollback()
            print(f"Error submitting swap request: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(traceback.format_exc())
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
        flash("Request updated successfully!", "success")
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
    if not is_logged_in():
        return redirect(url_for('main.login'))
    return render_template('map.html', logged_in=is_logged_in())

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
    
    # Fetch activity logs from the database
    
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

    timestamp = datetime.utcnow().strftime('%B %d, %Y, %I:%M %p')
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

    timestamp = datetime.utcnow().strftime('%B %d, %Y, %I:%M %p')
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


@main.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def view_profile(user_id):
    profile_user = User.query.get_or_404(user_id)

    if not is_logged_in():
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        content = request.form.get('comment')
        if not content or len(content) > 500:
            flash('Comment must be 1–500 characters', 'error')
        else:
            new_comment = ProfileComment(
                profile_id=user_id,
                author_id=session['user_id'],
                content=content
            )
            db.session.add(new_comment)

            if user_id != session['user_id']:  # Don't notify yourself
                create_notification(
                    user_id=user_id,
                    message=f"You received a new comment on your profile",
                    notification_type='new_comment'
                )
            
            db.session.commit()
            flash('Comment posted!', 'success')
            

        return redirect(url_for('main.view_profile', user_id=user_id))

    comments = ProfileComment.query.filter_by(
        profile_id=user_id,
        is_deleted=False
    ).order_by(ProfileComment.timestamp.asc()).all()

    myt = timezone(timedelta(hours=8))
    for comment in comments:
        comment.local_timestamp = comment.timestamp.replace(tzinfo=timezone.utc).astimezone(myt)
    

    return render_template(
    'comment.html',
    profile=profile_user,
    comments=comments,
    is_logged_in=is_logged_in
)

@main.route('/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    comment = ProfileComment.query.get_or_404(comment_id)

    # Optional: Check if the current user is the author
    if comment.author_id != session.get('user_id'):
        flash('You are not authorized to delete this comment.', 'error')
        return redirect(url_for('main.view_profile', user_id=comment.profile_id))

    # Soft delete implementation
    comment.is_deleted = True
    comment.deleted_at = datetime.utcnow()
    comment.deleted_by = session.get('user_id')
    
    db.session.commit()
    flash('Comment deleted.', 'success')
    return redirect(url_for('main.view_profile', user_id=comment.profile_id))

@main.route('/settings', methods=['GET', 'POST'])
def settings():
    if not is_logged_in():
        flash('Please log in to access settings', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.get(session['user_id'])

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

    return render_template('settings.html')

