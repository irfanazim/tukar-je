from . import db
from datetime import datetime, timedelta

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    hostel = db.Column(db.String(10), nullable=False)
    block = db.Column(db.String(1), nullable=False)
    room = db.Column(db.String(10), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    is_deleted = db.Column(db.Boolean, default=False)  # Soft delete flag
    deleted_at = db.Column(db.DateTime)
    deleted_by_admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.Text, nullable=True)
    

    deleted_by_admin = db.relationship('Admin', backref=db.backref('deleted_students', lazy=True))
    swap_requests = db.relationship('SwapRequest', backref='user', cascade="all, delete-orphan", passive_deletes=True)
    notifications = db.relationship('Notification', backref='user', cascade="all, delete-orphan", passive_deletes=True)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')) 
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id')) 
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    current_hostel = db.Column(db.String(10), nullable=False)  
    current_block = db.Column(db.String(1), nullable=False)    
    current_room = db.Column(db.String(10), nullable=False)
    desired_hostel = db.Column(db.String(10), nullable=False)  
    desired_block = db.Column(db.String(1), nullable=False)    
    desired_room = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")  
    date = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)  # Soft delete flag
    deleted_at = db.Column(db.DateTime)  
    deleted_by_admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    
    deleted_by_admin = db.relationship('Admin', backref=db.backref('deleted_swap_requests', lazy=True))
    
    

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    admin = db.relationship('Admin', backref=db.backref('announcements', lazy=True))


class RoommateProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship('User', backref=db.backref('roommate_profile', uselist=False))
    about = db.Column(db.Text)
    gender = db.Column(db.String(20), nullable=False)
    course_level = db.Column(db.String(50))  
    faculty = db.Column(db.String(50))  
    year = db.Column(db.Integer, nullable=False)
    contact_method = db.Column(db.String(50), nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RoomReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    hostel = db.Column(db.String(10), nullable=False)
    block = db.Column(db.String(1), nullable=False)
    room = db.Column(db.String(10), nullable=False)
    issue_type = db.Column(db.String(50), nullable=False)  # e.g., 'electrical', 'plumbing', 'furniture'
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False, default='medium')  # high, medium, low
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, in_progress, resolved
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    date_resolved = db.Column(db.DateTime)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    admin_notes = db.Column(db.Text)
    
    user = db.relationship('User', backref=db.backref('room_reports', lazy=True))
    admin = db.relationship('Admin', backref=db.backref('resolved_reports', lazy=True))

    @property
    def date_reported_my(self):
        return self.date_reported + timedelta(hours=8) if self.date_reported else None

    @property
    def date_resolved_my(self):
        return self.date_resolved + timedelta(hours=8) if self.date_resolved else None

class AdminActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)  
    entity_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(db.Text)  

    admin = db.relationship('Admin', backref=db.backref('activities', lazy=True))

class ProfileComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Profile being commented on
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   # User who wrote the comment
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)  # New field
    deleted_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    

    # Relationships
    profile = db.relationship('User', foreign_keys=[profile_id], backref=db.backref('comments_received', lazy=True))
    author = db.relationship('User', foreign_keys=[author_id], backref=db.backref('comments_written', lazy=True))