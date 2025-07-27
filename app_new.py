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

# Initialize extensions
db = SQLAlchemy(app)
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
    last_login = db.Column(db.DateTime)
    
    # Relationships
    leave_requests = db.relationship('LeaveRequest', foreign_keys='LeaveRequest.user_id', backref='employee', lazy='dynamic')
    managed_requests = db.relationship('LeaveRequest', foreign_keys='LeaveRequest.manager_id', backref='manager', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def get_leave_balance(self):
        # Calculate remaining leave days (assuming 30 days per year)
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
    details = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<AuditLog {self.id} - {self.action}>'

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')
    ])
    role = SelectField('Role', choices=[
        ('employee', 'Employee'), 
        ('manager', 'Manager'), 
        ('admin', 'Admin')
    ], validators=[DataRequired()])
    team = StringField('Team', validators=[Length(max=50)])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class LeaveRequestForm(FlaskForm):
    start_date = DateField('Start Date', validators=[DataRequired()])
    end_date = DateField('End Date', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired(), Length(min=10, max=500)])
    submit = SubmitField('Submit Request')
    
    def validate_start_date(self, field):
        if field.data < date.today():
            raise ValidationError('Start date cannot be in the past.')
    
    def validate_end_date(self, field):
        if hasattr(self, 'start_date') and self.start_date.data and field.data < self.start_date.data:
            raise ValidationError('End date cannot be before start date.')

class DecisionForm(FlaskForm):
    decision = SelectField('Decision', choices=[('approved', 'Approve'), ('rejected', 'Reject')], validators=[DataRequired()])
    decision_reason = TextAreaField('Comment', validators=[Length(max=500)])
    submit = SubmitField('Submit Decision')

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action, details=None):
    """Log user actions for audit trail"""
    if current_user.is_authenticated:
        audit = AuditLog(
            user_id=current_user.id,
            action=action,
            ip_address=get_user_ip(),
            details=details
        )
        db.session.add(audit)
        db.session.commit()

def role_required(role):
    """Decorator to restrict access by role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('Access denied. Insufficient permissions.', 'danger')
                return redirect(url_for('auth.login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_ip():
    """Get user IP address"""
    return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

# Authentication Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            team=form.team.data if form.team.data else None
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'Registration successful! Welcome {user.username}. Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_action(f'User logged in')
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'manager':
                return redirect(url_for('manager_dashboard'))
            else:
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('auth/login_new.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_action(f'User logged out')
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    else:
        return redirect(url_for('employee_dashboard'))

# Employee Routes
@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    # Get user's leave requests
    leave_requests = LeaveRequest.query.filter_by(user_id=current_user.id).order_by(LeaveRequest.applied_on.desc()).all()
    
    # Calculate statistics
    total_requests = len(leave_requests)
    approved_requests = len([r for r in leave_requests if r.status == 'approved'])
    pending_requests = len([r for r in leave_requests if r.status == 'pending'])
    rejected_requests = len([r for r in leave_requests if r.status == 'rejected'])
    leave_balance = current_user.get_leave_balance()
    
    return render_template('employee/dashboard_new.html', 
                         leave_requests=leave_requests,
                         total_requests=total_requests,
                         approved_requests=approved_requests,
                         pending_requests=pending_requests,
                         rejected_requests=rejected_requests,
                         leave_balance=leave_balance)

@app.route('/employee/apply-leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    form = LeaveRequestForm()
    if form.validate_on_submit():
        # Check leave balance
        days_requested = (form.end_date.data - form.start_date.data).days + 1
        if current_user.get_leave_balance() < days_requested:
            flash(f'Insufficient leave balance. You have {current_user.get_leave_balance()} days remaining.', 'warning')
            return render_template('employee/apply_leave.html', form=form)
        
        leave_request = LeaveRequest(
            user_id=current_user.id,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            reason=form.reason.data
        )
        db.session.add(leave_request)
        db.session.commit()
        
        log_action(f'Applied for leave from {form.start_date.data} to {form.end_date.data}', 
                  f'Days: {days_requested}, Reason: {form.reason.data[:50]}...')
        flash('Leave request submitted successfully!', 'success')
        return redirect(url_for('employee_dashboard'))
    
    return render_template('employee/apply_leave.html', form=form, leave_balance=current_user.get_leave_balance())

@app.route('/employee/edit-leave/<int:leave_id>', methods=['GET', 'POST'])
@login_required
def edit_leave(leave_id):
    leave_request = LeaveRequest.query.get_or_404(leave_id)
    
    # Check permissions
    if leave_request.user_id != current_user.id or leave_request.status != 'pending':
        flash('You can only edit your own pending leave requests.', 'danger')
        return redirect(url_for('employee_dashboard'))
    
    form = LeaveRequestForm(obj=leave_request)
    if form.validate_on_submit():
        leave_request.start_date = form.start_date.data
        leave_request.end_date = form.end_date.data
        leave_request.reason = form.reason.data
        db.session.commit()
        
        log_action(f'Edited leave request #{leave_id}')
        flash('Leave request updated successfully!', 'success')
        return redirect(url_for('employee_dashboard'))
    
    return render_template('employee/edit_leave.html', form=form, leave_request=leave_request)

@app.route('/employee/cancel-leave/<int:leave_id>')
@login_required
def cancel_leave(leave_id):
    leave_request = LeaveRequest.query.get_or_404(leave_id)
    
    # Check permissions
    if leave_request.user_id != current_user.id or leave_request.status != 'pending':
        flash('You can only cancel your own pending leave requests.', 'danger')
        return redirect(url_for('employee_dashboard'))
    
    db.session.delete(leave_request)
    db.session.commit()
    
    log_action(f'Cancelled leave request #{leave_id}')
    flash('Leave request cancelled successfully!', 'info')
    return redirect(url_for('employee_dashboard'))

# Manager Routes
@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role not in ['manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get team leave requests
    if current_user.role == 'admin':
        # Admin can see all requests - specify the join condition explicitly
        leave_requests = LeaveRequest.query.join(User, LeaveRequest.user_id == User.id).order_by(LeaveRequest.applied_on.desc()).all()
    else:
        # Manager sees requests from their team - specify the join condition explicitly
        leave_requests = LeaveRequest.query.join(User, LeaveRequest.user_id == User.id).filter(
            User.team == current_user.team,
            User.role == 'employee'
        ).order_by(LeaveRequest.applied_on.desc()).all()
    
    # Apply filters
    status_filter = request.args.get('status', '')
    employee_filter = request.args.get('employee', '')
    start_date_filter = request.args.get('start_date', '')
    end_date_filter = request.args.get('end_date', '')
    
    if status_filter:
        leave_requests = [r for r in leave_requests if r.status == status_filter]
    
    if employee_filter:
        leave_requests = [r for r in leave_requests if employee_filter.lower() in r.employee.username.lower()]
    
    if start_date_filter:
        start_date = datetime.strptime(start_date_filter, '%Y-%m-%d').date()
        leave_requests = [r for r in leave_requests if r.start_date >= start_date]
    
    if end_date_filter:
        end_date = datetime.strptime(end_date_filter, '%Y-%m-%d').date()
        leave_requests = [r for r in leave_requests if r.end_date <= end_date]
    
    # Get team employees for filter dropdown
    if current_user.role == 'admin':
        team_employees = User.query.filter_by(role='employee').all()
    else:
        team_employees = User.query.filter_by(team=current_user.team, role='employee').all()
    
    return render_template('manager/dashboard.html', 
                         leave_requests=leave_requests,
                         team_employees=team_employees,
                         filters={
                             'status': status_filter,
                             'employee': employee_filter,
                             'start_date': start_date_filter,
                             'end_date': end_date_filter
                         })

@app.route('/manager/decide-leave/<int:leave_id>', methods=['GET', 'POST'])
@login_required
def decide_leave(leave_id):
    if current_user.role not in ['manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    leave_request = LeaveRequest.query.get_or_404(leave_id)
    
    # Check if manager can decide on this request
    if current_user.role == 'manager' and leave_request.employee.team != current_user.team:
        flash('You can only decide on leave requests from your team.', 'danger')
        return redirect(url_for('manager_dashboard'))
    
    if leave_request.status != 'pending':
        flash('This leave request has already been decided.', 'warning')
        return redirect(url_for('manager_dashboard'))
    
    form = DecisionForm()
    if form.validate_on_submit():
        leave_request.status = form.decision.data
        leave_request.manager_id = current_user.id
        leave_request.decision_reason = form.decision_reason.data
        leave_request.decided_at = datetime.utcnow()
        db.session.commit()
        
        log_action(f'{form.decision.data.title()} leave request #{leave_id} for {leave_request.employee.username}', 
                  f'Comment: {form.decision_reason.data or "No comment"}')
        flash(f'Leave request {form.decision.data} successfully!', 'success')
        return redirect(url_for('manager_dashboard'))
    
    return render_template('manager/decide_leave.html', form=form, leave_request=leave_request)

# Admin Routes
@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    total_employees = User.query.filter_by(role='employee').count()
    total_managers = User.query.filter_by(role='manager').count()
    
    total_requests = LeaveRequest.query.count()
    pending_requests = LeaveRequest.query.filter_by(status='pending').count()
    approved_requests = LeaveRequest.query.filter_by(status='approved').count()
    rejected_requests = LeaveRequest.query.filter_by(status='rejected').count()
    
    # Calculate approval rate
    approval_rate = round((approved_requests / total_requests * 100) if total_requests > 0 else 0, 1)
    
    # Get team-wise statistics
    teams = db.session.query(User.team).filter(User.team.isnot(None)).distinct().all()
    team_stats = []
    for team in teams:
        team_name = team[0]
        team_requests = LeaveRequest.query.join(User, LeaveRequest.user_id == User.id).filter(User.team == team_name).count()
        team_stats.append({'name': team_name, 'requests': team_requests})
    
    # Get recent activity
    recent_requests = LeaveRequest.query.order_by(LeaveRequest.applied_on.desc()).limit(5).all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('admin/dashboard_new.html',
                         total_users=total_users,
                         total_employees=total_employees,
                         total_managers=total_managers,
                         total_requests=total_requests,
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         rejected_requests=rejected_requests,
                         approval_rate=approval_rate,
                         team_stats=team_stats,
                         recent_requests=recent_requests,
                         recent_logs=recent_logs)

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            team=form.team.data if form.team.data else None
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        log_action(f'Added new user: {user.username} ({user.role})')
        flash(f'User {user.username} added successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/add_user.html', form=form)

@app.route('/admin/delete-user/<int:user_id>')
@login_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Soft delete by deactivating
    user.is_active = False
    db.session.commit()
    
    log_action(f'Deactivated user: {user.username} ({user.role})')
    flash(f'User {user.username} deactivated successfully!', 'info')
    return redirect(url_for('admin_users'))

@app.route('/admin/audit-logs')
@login_required
@role_required('admin')
def audit_logs():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('admin/audit_logs.html', logs=logs)

# API Routes for real-time updates
@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    """API endpoint for real-time dashboard updates"""
    if current_user.role == 'employee':
        leave_requests = LeaveRequest.query.filter_by(user_id=current_user.id).all()
        stats = {
            'total_requests': len(leave_requests),
            'approved_requests': len([r for r in leave_requests if r.status == 'approved']),
            'pending_requests': len([r for r in leave_requests if r.status == 'pending']),
            'rejected_requests': len([r for r in leave_requests if r.status == 'rejected']),
            'leave_balance': current_user.get_leave_balance()
        }
    elif current_user.role in ['manager', 'admin']:
        if current_user.role == 'admin':
            leave_requests = LeaveRequest.query.all()
        else:
            leave_requests = LeaveRequest.query.join(User).filter(User.team == current_user.team).all()
        
        stats = {
            'total_requests': len(leave_requests),
            'pending_requests': len([r for r in leave_requests if r.status == 'pending']),
            'approved_requests': len([r for r in leave_requests if r.status == 'approved']),
            'rejected_requests': len([r for r in leave_requests if r.status == 'rejected'])
        }
    
    return jsonify(stats)

@app.route('/api/leave-requests')
@login_required
def api_leave_requests():
    """API endpoint to get leave requests for current user's scope"""
    if current_user.role == 'employee':
        requests = LeaveRequest.query.filter_by(user_id=current_user.id).order_by(LeaveRequest.applied_on.desc()).all()
    elif current_user.role == 'admin':
        requests = LeaveRequest.query.join(User, LeaveRequest.user_id == User.id).order_by(LeaveRequest.applied_on.desc()).all()
    else:  # manager
        requests = LeaveRequest.query.join(User, LeaveRequest.user_id == User.id).filter(
            User.team == current_user.team, User.role == 'employee'
        ).order_by(LeaveRequest.applied_on.desc()).all()
    
    data = []
    for req in requests:
        data.append({
            'id': req.id,
            'employee': req.employee.username,
            'start_date': req.start_date.strftime('%Y-%m-%d'),
            'end_date': req.end_date.strftime('%Y-%m-%d'),
            'days': req.days_count,
            'status': req.status,
            'status_class': req.status_class,
            'applied_on': req.applied_on.strftime('%Y-%m-%d %H:%M'),
            'reason': req.reason[:50] + '...' if len(req.reason) > 50 else req.reason
        })
    
    return jsonify(data)

# Export Routes
@app.route('/reports/export-csv')
@login_required
@role_required('admin')
def export_csv():
    # Get filter parameters
    month = request.args.get('month')
    team = request.args.get('team')
    
    # Build query with explicit join condition
    query = db.session.query(
        LeaveRequest.id,
        User.username.label('employee_username'),
        User.team,
        LeaveRequest.start_date,
        LeaveRequest.end_date,
        LeaveRequest.reason,
        LeaveRequest.status,
        LeaveRequest.applied_on
    ).join(User, LeaveRequest.user_id == User.id)
    
    # Apply filters
    if month:
        year, month_num = month.split('-')
        query = query.filter(
            db.extract('year', LeaveRequest.applied_on) == int(year),
            db.extract('month', LeaveRequest.applied_on) == int(month_num)
        )
    
    if team:
        query = query.filter(User.team == team)
    
    # Execute query and create DataFrame
    results = query.all()
    df = pd.DataFrame([{
        'Request ID': r.id,
        'Employee': r.employee_username,
        'Team': r.team,
        'Start Date': r.start_date,
        'End Date': r.end_date,
        'Days': (r.end_date - r.start_date).days + 1,
        'Reason': r.reason,
        'Status': r.status.title(),
        'Applied Date': r.applied_on.strftime('%Y-%m-%d %H:%M')
    } for r in results])
    
    # Create CSV response
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    log_action(f'Exported leave data to CSV')
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=leave_requests.csv'
    return response

# Initialize database and create tables
def init_db():
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully!")

if __name__ == '__main__':
    init_db()
    print("🚀 Employee Leave Management System starting...")
    print("📊 You can view the SQLite database using DB Browser for SQLite")
    print("💾 Database file: leaves.db")
    print("🌐 Access the application at: http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
