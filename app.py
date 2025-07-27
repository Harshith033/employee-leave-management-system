from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import pandas as pd
import os
from functools import wraps
from io import BytesIO

# WeasyPrint will be imported later when needed
WEASYPRINT_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, manager, employee
    team = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    leave_requests = db.relationship('LeaveRequest', foreign_keys='LeaveRequest.user_id', backref='employee', lazy='dynamic')
    managed_requests = db.relationship('LeaveRequest', foreign_keys='LeaveRequest.manager_id', backref='manager', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    decision_reason = db.Column(db.Text, nullable=True)
    decided_at = db.Column(db.DateTime, nullable=True)
    
    @property
    def days_count(self):
        return (self.end_date - self.start_date).days + 1

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=False)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
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

class UserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('employee', 'Employee'), ('manager', 'Manager'), ('admin', 'Admin')], validators=[DataRequired()])
    team = StringField('Team', validators=[Length(max=50)])
    submit = SubmitField('Add User')

class DecisionForm(FlaskForm):
    decision = SelectField('Decision', choices=[('approved', 'Approve'), ('rejected', 'Reject')], validators=[DataRequired()])
    decision_reason = TextAreaField('Comment (Optional)', validators=[Length(max=500)])
    submit = SubmitField('Submit Decision')

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action, ip_address):
    """Log user actions for audit trail"""
    if current_user.is_authenticated:
        audit = AuditLog(
            user_id=current_user.id,
            action=action,
            ip_address=ip_address
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
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_ip():
    """Get user IP address"""
    return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            log_action(f'User logged in', get_user_ip())
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_action(f'User logged out', get_user_ip())
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    else:
        return redirect(url_for('employee_dashboard'))

@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    if current_user.role not in ['employee', 'manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get user's leave requests
    leave_requests = LeaveRequest.query.filter_by(user_id=current_user.id).order_by(LeaveRequest.applied_at.desc()).all()
    
    # Calculate statistics
    total_requests = len(leave_requests)
    approved_requests = len([r for r in leave_requests if r.status == 'approved'])
    pending_requests = len([r for r in leave_requests if r.status == 'pending'])
    
    return render_template('employee/dashboard.html', 
                         leave_requests=leave_requests,
                         total_requests=total_requests,
                         approved_requests=approved_requests,
                         pending_requests=pending_requests)

@app.route('/employee/apply-leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    if current_user.role not in ['employee', 'manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = LeaveRequestForm()
    if form.validate_on_submit():
        leave_request = LeaveRequest(
            user_id=current_user.id,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            reason=form.reason.data
        )
        db.session.add(leave_request)
        db.session.commit()
        
        log_action(f'Applied for leave from {form.start_date.data} to {form.end_date.data}', get_user_ip())
        flash('Leave request submitted successfully!', 'success')
        return redirect(url_for('employee_dashboard'))
    
    return render_template('employee/apply_leave.html', form=form)

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
        
        log_action(f'Edited leave request #{leave_id}', get_user_ip())
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
    
    log_action(f'Cancelled leave request #{leave_id}', get_user_ip())
    flash('Leave request cancelled successfully!', 'info')
    return redirect(url_for('employee_dashboard'))

@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role not in ['manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get team leave requests
    if current_user.role == 'admin':
        # Admin can see all requests
        leave_requests = LeaveRequest.query.join(User).order_by(LeaveRequest.applied_at.desc()).all()
    else:
        # Manager sees requests from their team
        leave_requests = LeaveRequest.query.join(User).filter(
            User.team == current_user.team,
            User.role == 'employee'
        ).order_by(LeaveRequest.applied_at.desc()).all()
    
    # Apply filters
    status_filter = request.args.get('status', '')
    employee_filter = request.args.get('employee', '')
    
    if status_filter:
        leave_requests = [r for r in leave_requests if r.status == status_filter]
    
    if employee_filter:
        leave_requests = [r for r in leave_requests if employee_filter.lower() in r.employee.name.lower()]
    
    # Get team employees for filter dropdown
    if current_user.role == 'admin':
        team_employees = User.query.filter_by(role='employee').all()
    else:
        team_employees = User.query.filter_by(team=current_user.team, role='employee').all()
    
    return render_template('manager/dashboard.html', 
                         leave_requests=leave_requests,
                         team_employees=team_employees,
                         status_filter=status_filter,
                         employee_filter=employee_filter)

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
        
        log_action(f'{form.decision.data.title()} leave request #{leave_id} for {leave_request.employee.name}', get_user_ip())
        flash(f'Leave request {form.decision.data} successfully!', 'success')
        return redirect(url_for('manager_dashboard'))
    
    return render_template('manager/decide_leave.html', form=form, leave_request=leave_request)

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
    
    # Get recent activity
    recent_requests = LeaveRequest.query.order_by(LeaveRequest.applied_at.desc()).limit(5).all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_employees=total_employees,
                         total_managers=total_managers,
                         total_requests=total_requests,
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         rejected_requests=rejected_requests,
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
    form = UserForm()
    if form.validate_on_submit():
        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'danger')
            return render_template('admin/add_user.html', form=form)
        
        user = User(
            name=form.name.data,
            email=form.email.data,
            role=form.role.data,
            team=form.team.data if form.team.data else None
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        log_action(f'Added new user: {user.name} ({user.role})', get_user_ip())
        flash(f'User {user.name} added successfully!', 'success')
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
    
    # Delete associated leave requests and audit logs
    LeaveRequest.query.filter_by(user_id=user_id).delete()
    AuditLog.query.filter_by(user_id=user_id).delete()
    
    log_action(f'Deleted user: {user.name} ({user.role})', get_user_ip())
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.name} deleted successfully!', 'info')
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

@app.route('/reports/export-csv')
@login_required
@role_required('admin')
def export_csv():
    # Get filter parameters
    month = request.args.get('month')
    team = request.args.get('team')
    employee_id = request.args.get('employee_id')
    
    # Build query
    query = db.session.query(
        LeaveRequest.id,
        User.name.label('employee_name'),
        User.team,
        LeaveRequest.start_date,
        LeaveRequest.end_date,
        LeaveRequest.reason,
        LeaveRequest.status,
        LeaveRequest.applied_at
    ).join(User, LeaveRequest.user_id == User.id)
    
    # Apply filters
    if month:
        year, month_num = month.split('-')
        query = query.filter(
            db.extract('year', LeaveRequest.applied_at) == int(year),
            db.extract('month', LeaveRequest.applied_at) == int(month_num)
        )
    
    if team:
        query = query.filter(User.team == team)
    
    if employee_id:
        query = query.filter(User.id == int(employee_id))
    
    # Execute query and create DataFrame
    results = query.all()
    df = pd.DataFrame([{
        'Request ID': r.id,
        'Employee': r.employee_name,
        'Team': r.team,
        'Start Date': r.start_date,
        'End Date': r.end_date,
        'Reason': r.reason,
        'Status': r.status.title(),
        'Applied Date': r.applied_at.strftime('%Y-%m-%d %H:%M')
    } for r in results])
    
    # Create CSV response
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    log_action(f'Exported leave data to CSV', get_user_ip())
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=leave_requests.csv'
    return response

@app.route('/reports/export-pdf')
@login_required
@role_required('admin')
def export_pdf():
    # Get filter parameters
    month = request.args.get('month')
    team = request.args.get('team')
    
    # Build query
    query = db.session.query(
        LeaveRequest.id,
        User.name.label('employee_name'),
        User.team,
        LeaveRequest.start_date,
        LeaveRequest.end_date,
        LeaveRequest.reason,
        LeaveRequest.status,
        LeaveRequest.applied_at
    ).join(User, LeaveRequest.user_id == User.id)
    
    # Apply filters
    if month:
        year, month_num = month.split('-')
        query = query.filter(
            db.extract('year', LeaveRequest.applied_at) == int(year),
            db.extract('month', LeaveRequest.applied_at) == int(month_num)
        )
    
    if team:
        query = query.filter(User.team == team)
    
    results = query.all()
    
    # Render HTML template for PDF
    html_content = render_template('reports/pdf_template.html', 
                                 requests=results,
                                 month=month,
                                 team=team,
                                 generated_at=datetime.now())
    
    log_action(f'Exported leave data to HTML report', get_user_ip())
    
    # For now, return as HTML (can be printed to PDF by user)
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/api/teams')
@login_required
def api_teams():
    """API endpoint to get list of teams"""
    teams = db.session.query(User.team).filter(User.team.isnot(None)).distinct().all()
    return jsonify([team[0] for team in teams if team[0]])

@app.route('/api/employees')
@login_required
def api_employees():
    """API endpoint to get list of employees"""
    employees = User.query.filter_by(role='employee').all()
    return jsonify([{'id': emp.id, 'name': emp.name, 'team': emp.team} for emp in employees])

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create default admin user if none exists
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(
                name='Admin User',
                email='admin@elms.com',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            
            # Create sample manager
            manager = User(
                name='John Manager',
                email='manager@elms.com',
                role='manager',
                team='Engineering'
            )
            manager.set_password('manager123')
            db.session.add(manager)
            
            # Create sample employee
            employee = User(
                name='Jane Employee',
                email='employee@elms.com',
                role='employee',
                team='Engineering'
            )
            employee.set_password('employee123')
            db.session.add(employee)
            
            db.session.commit()
            print("Default users created:")
            print("Admin: admin@elms.com / admin123")
            print("Manager: manager@elms.com / manager123")
            print("Employee: employee@elms.com / employee123")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
