# Employee Leave Management System (ELMS)

A comprehensive, role-based Flask web application for managing employee leave requests with real-time status tracking, audit logs, and reporting capabilities.

## 🌟 Features

### 🔐 Role-Based Access Control
- **Admin**: Full system access, user management, analytics, and reporting
- **Manager**: Team leave request approval/rejection and team oversight
- **Employee**: Leave application, status tracking, and request management

### 🚀 Core Functionality
- **Authentication**: Secure login/logout with Flask-Login
- **Leave Management**: Apply, edit, cancel, approve/reject leave requests
- **Real-time Status**: Track leave request status (pending, approved, rejected)
- **Audit Logging**: Complete activity tracking with IP addresses and timestamps
- **Reporting**: Export data to CSV and PDF formats
- **Responsive UI**: Bootstrap 5-based modern interface

## 🛠️ Tech Stack

- **Backend**: Python, Flask, SQLAlchemy
- **Frontend**: HTML5, Jinja2, Bootstrap 5, JavaScript
- **Database**: SQLite (development) / PostgreSQL (production-ready)
- **Authentication**: Flask-Login (session-based)
- **Forms**: Flask-WTF with CSRF protection
- **Reporting**: pandas (CSV), WeasyPrint (PDF)
- **UI Framework**: Bootstrap 5 with custom styling

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git (optional, for cloning)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or download the project
cd employee-Leave-MS

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Running the Application

```bash
# Run the Flask application
python app.py
```

The application will start on `http://localhost:5000`

### 3. Default Login Credentials

The system creates default users for testing:

| Role | Email | Password | Description |
|------|-------|----------|-------------|
| Admin | admin@elms.com | admin123 | Full system access |
| Manager | manager@elms.com | manager123 | Team management |
| Employee | employee@elms.com | employee123 | Basic employee access |

## 📱 User Interfaces

### Employee Dashboard
- Apply for leave with date validation
- View leave request history
- Edit/cancel pending requests
- Real-time status updates

### Manager Dashboard  
- View team leave requests
- Filter by employee, status, and date
- Approve/reject requests with comments
- Team leave analytics

### Admin Dashboard
- System-wide analytics and metrics
- User management (add/delete users)
- Audit log monitoring
- Export reports (CSV/PDF)
- Complete system oversight

## 🗃️ Database Schema

### User Model
- `id`: Primary key
- `name`: Full name
- `email`: Unique email address
- `password_hash`: Encrypted password
- `role`: admin/manager/employee
- `team`: Optional team assignment
- `created_at`: Registration timestamp

### LeaveRequest Model
- `id`: Primary key
- `user_id`: Foreign key to User
- `start_date`: Leave start date
- `end_date`: Leave end date
- `reason`: Leave justification
- `status`: pending/approved/rejected
- `manager_id`: Approving manager
- `applied_at`: Application timestamp
- `decision_reason`: Manager's comment

### AuditLog Model
- `id`: Primary key
- `user_id`: Foreign key to User
- `action`: Description of action
- `timestamp`: When action occurred
- `ip_address`: User's IP address

## 🔒 Security Features

- **CSRF Protection**: All forms protected with Flask-WTF
- **Password Hashing**: Werkzeug secure password hashing
- **Session Management**: Flask-Login secure sessions
- **Role-based Access**: Decorator-based permission system
- **Audit Logging**: Complete activity tracking
- **Input Validation**: Server-side validation for all inputs

## 📊 Reporting Features

### CSV Export
- Filter by month, team, or employee
- Complete leave request data
- Import-ready format for Excel

### PDF Reports
- Professional formatted reports
- Summary statistics included
- Print-ready layout
- Filtered data export

## 🎨 UI/UX Features

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Modern Interface**: Bootstrap 5 with custom styling
- **Interactive Elements**: Real-time form validation
- **Status Indicators**: Color-coded status badges
- **Loading States**: User feedback during operations
- **Accessibility**: ARIA labels and keyboard navigation

## 🔧 Configuration

### Database Configuration
```python
# SQLite (default)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elms.db'

# PostgreSQL (production)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@host:port/dbname'
```

### Secret Key
```python
# Change this for production
app.config['SECRET_KEY'] = 'your-secret-key-here'
```

## 🚀 Deployment

### Local Development
```bash
python app.py
```

### Production Deployment
1. Set environment variables for production
2. Use production database (PostgreSQL)
3. Configure proper secret key
4. Use WSGI server (Gunicorn)
5. Set up reverse proxy (Nginx)

### Docker Deployment (Optional)
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

## 📝 API Endpoints

### Authentication
- `GET /login` - Login page
- `POST /login` - Process login
- `GET /logout` - Logout user

### Employee Routes
- `GET /employee/dashboard` - Employee dashboard
- `GET /employee/apply-leave` - Leave application form
- `POST /employee/apply-leave` - Submit leave request
- `GET /employee/edit-leave/<id>` - Edit leave form
- `POST /employee/edit-leave/<id>` - Update leave request
- `GET /employee/cancel-leave/<id>` - Cancel leave request

### Manager Routes
- `GET /manager/dashboard` - Manager dashboard
- `GET /manager/decide-leave/<id>` - Review leave form
- `POST /manager/decide-leave/<id>` - Approve/reject leave

### Admin Routes
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/users` - User management
- `GET /admin/add-user` - Add user form
- `POST /admin/add-user` - Create new user
- `GET /admin/delete-user/<id>` - Delete user
- `GET /admin/audit-logs` - Audit log viewer

### Reporting Routes
- `GET /reports/export-csv` - Export CSV report
- `GET /reports/export-pdf` - Export PDF report

## 🧪 Testing

### Manual Testing
1. Test all user roles and permissions
2. Verify leave request workflow
3. Check audit logging functionality
4. Test report generation
5. Validate form submissions and error handling

### Automated Testing (Future Enhancement)
```bash
# Install testing dependencies
pip install pytest pytest-flask

# Run tests
pytest tests/
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🐛 Troubleshooting

### Common Issues

**Database Issues**
```bash
# Reset database
rm elms.db
python app.py
```

**Permission Errors**
- Ensure proper role assignment in database
- Check route decorators for role requirements

**Module Import Errors**
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

**Port Already in Use**
```bash
# Change port in app.py
app.run(debug=True, port=5001)
```

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the documentation

## 🎯 Future Enhancements

- [ ] Email notifications for leave approvals/rejections
- [ ] Calendar integration
- [ ] Mobile app development
- [ ] Advanced analytics dashboard
- [ ] Multi-language support
- [ ] Leave balance tracking
- [ ] Holiday calendar integration
- [ ] Bulk operations for managers
- [ ] API development for external integrations
- [ ] Advanced reporting with charts and graphs

---

**Built with ❤️ using Flask and Bootstrap**
