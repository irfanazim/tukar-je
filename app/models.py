from . import db
from datetime import datetime

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

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) 
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(50))
    
class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    current_hostel = db.Column(db.String(10), nullable=False)  
    current_block = db.Column(db.String(1), nullable=False)    
    current_room = db.Column(db.String(10), nullable=False)
    desired_hostel = db.Column(db.String(10), nullable=False)  
    desired_block = db.Column(db.String(1), nullable=False)    
    desired_room = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")  
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with User model
    user = db.relationship('User', backref=db.backref('swap_requests', lazy=True))