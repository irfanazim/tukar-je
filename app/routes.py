from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, session, current_app
from . import db, mail
from .models import Notification, User, Admin
from .utils import (get_admin_notifications, create_notification, get_user_notifications, is_valid_mmu_email, is_logged_in, is_admin_logged_in, 
                   setup_user_session, setup_admin_session, generate_token,
                   send_email, send_2fa_email,
                   send_verification_email)
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from math import ceil
from datetime import datetime
from app.models import SwapRequest
from sqlalchemy import func

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html', 
                        logged_in=is_logged_in(),
                        admin_logged_in=is_admin_logged_in())

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
    create_notification(
        user_id=user.id,
        message="You have successfully logged in to your account.",
        notification_type='login'
    )
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
    swap_requests = SwapRequest.query.filter_by(user_id=user_id).all()
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
        
    return render_template('notification.html', notifications=notifications)
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
    per_page = 5

    query = SwapRequest.query
    #searching
    if search:
        query = query.filter(func.lower(SwapRequest.name).like(f"%{search}%"))
    #filtering by status
    if status != 'all':
        query = query.filter_by(status=status)
    #sorting 
    if sort == 'name_asc':
        query = query.order_by(SwapRequest.name.asc())
    elif sort == 'name_desc':
        query = query.order_by(SwapRequest.name.desc())
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
        # Notify the user
        create_notification(
            user_id=swap.user_id,
            message=f"Your swap request to {swap.desired_hostel} (Block {swap.desired_block}, Room {swap.desired_room}) has been approved!",
            notification_type='swap_approved'
        )

    return redirect(request.referrer or url_for('main.swap_requests'))

@main.route('/admin/reject', methods=['POST'])
def reject_request():
    request_id = request.form.get('id')
    swap = SwapRequest.query.get(request_id)
    if swap:
        swap.status = "rejected"
        db.session.commit()
        # Notify the user
        create_notification(
            user_id=swap.user_id,
             message=f"Your swap request to {swap.desired_hostel} (Block {swap.desired_block}, Room {swap.desired_room}) has been rejected.",
            notification_type='swap_rejected'
        )
    return redirect(request.referrer or url_for('main.swap_requests'))

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
                message="Your swap request has been submitted successfully.",
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

# Admin routes
@main.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
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
            return redirect(url_for('main.swap_requests'))
            
        flash('Invalid username or password', 'error')
        return redirect(url_for('main.admin_login'))
        
    return render_template('admin_login.html')

@main.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('main.index'))
