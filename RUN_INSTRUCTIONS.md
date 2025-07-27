# Employee Leave Management System - Run Instructions

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Installation & Setup

1. **Navigate to the project directory:**
   ```bash
   cd "C:\Desktop\python works\employee-Leave-MS"
   ```

2. **Activate the virtual environment:**
   ```bash
   .venv\Scripts\activate
   ```

3. **Install dependencies (if not already installed):**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```

5. **Access the application:**
   Open your web browser and go to: `http://127.0.0.1:5000`

### Default Login Credentials

| Role | Email | Password | Access Level |
|------|-------|----------|--------------|
| **Admin** | admin@elms.com | admin123 | Full system access |
| **Manager** | manager@elms.com | manager123 | Team management |
| **Employee** | employee@elms.com | employee123 | Leave requests |

### Features Available

#### For Employees:
- ✅ Apply for leave with date validation
- ✅ View leave request status and history
- ✅ Edit pending leave requests
- ✅ Cancel pending requests

#### For Managers:
- ✅ View team leave requests
- ✅ Approve/reject requests with comments
- ✅ Filter requests by employee, status, date
- ✅ Access to employee dashboard features

#### For Administrators:
- ✅ Complete system overview and analytics
- ✅ User management (add/delete users)
- ✅ View all leave requests across teams
- ✅ Export data to CSV format
- ✅ Export reports to HTML (print-ready for PDF)
- ✅ Complete audit log monitoring
- ✅ Access to all user role features

### System Features

#### Security:
- 🔐 Secure authentication with password hashing
- 🛡️ Role-based access control
- 🔍 Complete audit logging with IP tracking
- 🚫 CSRF protection on all forms

#### User Interface:
- 📱 Responsive Bootstrap 5 design
- 🎨 Modern and intuitive interface
- ⚡ Real-time form validation
- 📊 Interactive dashboards with statistics

#### Data Management:
- 💾 SQLite database (ready for production upgrade)
- 📈 Comprehensive reporting system
- 📤 CSV export functionality
- 📄 HTML report generation (print-ready)

### Troubleshooting

#### If the application doesn't start:
1. Ensure Python 3.8+ is installed
2. Check that all dependencies are installed: `pip install -r requirements.txt`
3. Verify you're in the correct directory

#### If you can't access the application:
1. Check that the server is running (look for "Running on http://127.0.0.1:5000")
2. Ensure no other application is using port 5000
3. Try accessing `http://localhost:5000` instead

#### If login fails:
1. Use the exact credentials listed above
2. Ensure caps lock is off
3. Try refreshing the page

### Development Notes

- The application uses SQLite by default (file: `elms.db`)
- Debug mode is enabled for development
- All user passwords are securely hashed
- Session-based authentication with Flask-Login
- Audit logs track all important user actions

### Production Deployment

For production use:
1. Change the secret key in `app.py`
2. Set `debug=False`
3. Use a production database (PostgreSQL recommended)
4. Configure a proper WSGI server (Gunicorn)
5. Set up SSL/HTTPS
6. Configure environment variables

### Database Schema

The application uses three main models:
- **User**: Stores user information and roles
- **LeaveRequest**: Stores leave applications and decisions
- **AuditLog**: Tracks all system activities

### Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the README.md file for detailed documentation
3. Ensure all requirements are properly installed

---

**Built with Flask, Bootstrap 5, and modern web technologies** 🚀
