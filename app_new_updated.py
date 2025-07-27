from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
import pandas as pd
import os
from functools import wraps
from io import BytesIO
import secrets

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leaves.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, manager, employee
    team = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    leave_requests = db.relationship('LeaveRequest', foreign_keys='LeaveRequest.user_id', backref='employee', lazy='dynamic')
    managed_requests = db.relationship('LeaveRequest', foreign_keys='LeaveRequest.manager_id', backref='manager', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def get_leave_balance(self):
        current_year = datetime.now().year
        approved_leaves = LeaveRequest.query.filter_by(
            user_id=self.id, 
            status='approved'
        ).filter(
            db.extract('year', LeaveRequest.start_date) == current_year
        ).all()
        
        used_days = sum([(req.end_date - req.start_date).days + 1 for req in approved_leaves])
        return max(0, 30 - used_days)
    
    def __repr__(self):
        return f'<User {self.username}>'

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    decision_reason = db.Column(db.Text, nullable=True)
    applied_on = db.Column(db.DateTime, default=datetime.utcnow)
    decided_at = db.Column(db.DateTime, nullable=True)
    
    @property
    def days_count(self):
        return (self.end_date - self.start_date).days + 1
    
    @property
    def status_class(self):
        return {
            'pending': 'warning',
            'approved': 'success',
            'rejected': 'danger'
        }.get(self.status, 'secondary')
    
    def __repr__(self):
        return f'<LeaveRequest {self.id} - {self.status}>'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You need to be an admin to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'manager']:
            flash('You need to be a manager to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'manager':
            return redirect(url_for('manager_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
