# 📁 Project Structure - Employee Leave Management System

```
employee-Leave-MS/
├── 📄 app.py                    # Main Flask application file
├── 📄 config.py                 # Configuration settings
├── 📄 requirements.txt          # Python dependencies
├── 📄 README.md                 # Comprehensive project documentation
├── 📄 RUN_INSTRUCTIONS.md       # Quick start guide
├── 📄 PROJECT_STRUCTURE.md      # This file - project organization
├── 📄 .env.template            # Environment variables template
├── 📄 deploy.sh                # Linux/Mac deployment script
├── 📄 deploy.bat               # Windows deployment script
├── 📁 .venv/                   # Python virtual environment
├── 📄 elms.db                  # SQLite database (created on first run)
│
├── 📁 templates/               # Jinja2 HTML templates
│   ├── 📄 base.html            # Base template with navigation
│   │
│   ├── 📁 auth/                # Authentication templates
│   │   └── 📄 login.html       # Login page
│   │
│   ├── 📁 employee/            # Employee role templates
│   │   ├── 📄 dashboard.html   # Employee dashboard
│   │   ├── 📄 apply_leave.html # Leave application form
│   │   └── 📄 edit_leave.html  # Edit leave request
│   │
│   ├── 📁 manager/             # Manager role templates
│   │   ├── 📄 dashboard.html   # Manager dashboard
│   │   └── 📄 decide_leave.html # Leave approval/rejection
│   │
│   ├── 📁 admin/               # Admin role templates
│   │   ├── 📄 dashboard.html   # Admin dashboard
│   │   ├── 📄 users.html       # User management
│   │   ├── 📄 add_user.html    # Add new user
│   │   └── 📄 audit_logs.html  # Audit log viewer
│   │
│   └── 📁 reports/             # Report templates
│       └── 📄 pdf_template.html # HTML report template
│
└── 📁 static/                  # Static assets
    ├── 📁 css/                 # Stylesheets
    │   └── 📄 style.css        # Custom CSS styles
    │
    └── 📁 js/                  # JavaScript files
        └── 📄 script.js        # Custom JavaScript
```

## 🔧 Core Components

### **Main Application (`app.py`)**
- **Flask App Configuration**: Database, authentication, security
- **Database Models**: User, LeaveRequest, AuditLog
- **Forms**: Login, Leave Request, User Management, Decision forms
- **Routes**: All application endpoints organized by role
- **Helper Functions**: Role decorators, audit logging, IP tracking

### **Templates Structure**

#### **Base Template (`base.html`)**
- Bootstrap 5 responsive layout
- Dynamic navigation based on user role
- Flash message handling
- Common CSS/JS includes

#### **Authentication (`auth/`)**
- **login.html**: Secure login form with demo credentials

#### **Employee Interface (`employee/`)**
- **dashboard.html**: Statistics, quick actions, leave request table
- **apply_leave.html**: Leave application with date validation
- **edit_leave.html**: Edit pending requests

#### **Manager Interface (`manager/`)**
- **dashboard.html**: Team requests, filtering, decision making
- **decide_leave.html**: Detailed request review with approval/rejection

#### **Admin Interface (`admin/`)**
- **dashboard.html**: System overview, analytics, quick actions
- **users.html**: User management with role-based display
- **add_user.html**: New user creation with role selection
- **audit_logs.html**: Paginated audit log with filtering

#### **Reports (`reports/`)**
- **pdf_template.html**: Print-ready report layout

### **Static Assets**

#### **CSS (`static/css/style.css`)**
- Custom Bootstrap 5 enhancements
- Role-specific styling
- Responsive design improvements
- Animation and transition effects
- Print-ready styles

#### **JavaScript (`static/js/script.js`)**
- Form validation and enhancement
- Real-time date calculations
- Auto-hiding alerts
- Loading states
- Keyboard shortcuts
- Search functionality

## 🗄️ Database Schema

### **User Model**
```sql
- id (Primary Key)
- name (String, required)
- email (String, unique, required)
- password_hash (String, required)
- role (String: admin/manager/employee)
- team (String, optional)
- created_at (DateTime)
```

### **LeaveRequest Model**
```sql
- id (Primary Key)
- user_id (Foreign Key -> User)
- start_date (Date, required)
- end_date (Date, required)
- reason (Text, required)
- status (String: pending/approved/rejected)
- manager_id (Foreign Key -> User, optional)
- applied_at (DateTime)
- decision_reason (Text, optional)
- decided_at (DateTime, optional)
```

### **AuditLog Model**
```sql
- id (Primary Key)
- user_id (Foreign Key -> User)
- action (String, required)
- timestamp (DateTime)
- ip_address (String, required)
```

## 🚀 Application Features

### **Authentication & Security**
- Session-based authentication with Flask-Login
- Password hashing with Werkzeug
- CSRF protection on all forms
- Role-based access control
- IP address tracking
- Secure session configuration

### **Role-Based Access**

#### **Employee (Basic User)**
- Apply for leave with date validation
- View personal leave history
- Edit/cancel pending requests
- Dashboard with personal statistics

#### **Manager (Team Lead)**
- All employee features
- View team leave requests
- Approve/reject requests with comments
- Filter and search functionality
- Team analytics

#### **Admin (System Administrator)**
- All manager features
- Complete system overview
- User management (CRUD operations)
- Export functionality (CSV/HTML)
- Audit log monitoring
- System-wide analytics

### **Data Management**
- SQLite database (development)
- PostgreSQL ready (production)
- Data export to CSV
- HTML reports (print-ready for PDF)
- Complete audit trail

### **User Interface**
- Bootstrap 5 responsive design
- Modern, intuitive interface
- Real-time form validation
- Interactive dashboards
- Mobile-friendly layout
- Accessibility features

## 🔄 Workflow

### **Leave Request Process**
1. **Employee**: Apply for leave with dates and reason
2. **System**: Validate dates and create request (status: pending)
3. **Manager**: Review request details and team context
4. **Manager**: Approve/reject with optional comments
5. **System**: Update status and notify (audit log)
6. **Employee**: View decision and comments

### **User Management (Admin)**
1. **Admin**: Access user management panel
2. **Admin**: Add new user with role assignment
3. **System**: Create account with secure password
4. **System**: Log user creation action
5. **Admin**: Can delete users (except self)

### **Reporting & Analytics**
1. **Admin**: Access reporting dashboard
2. **Admin**: Apply filters (month, team, employee)
3. **System**: Generate filtered data
4. **Admin**: Export to CSV or HTML
5. **System**: Log export action

## 🛠️ Configuration

### **Environment Variables**
- **SECRET_KEY**: Flask secret key for sessions
- **DATABASE_URL**: Database connection string
- **MAIL_***: Email configuration (future feature)
- **LOG_LEVEL**: Logging level

### **Config Classes**
- **DevelopmentConfig**: Debug mode, SQLite
- **ProductionConfig**: Security optimized, PostgreSQL
- **TestingConfig**: Testing environment
- **HerokuConfig**: Cloud deployment ready

## 📊 Monitoring & Analytics

### **Audit Logging**
- All user actions tracked
- IP address recording
- Timestamp precision
- Action categorization
- Admin dashboard integration

### **System Metrics**
- User count by role
- Leave request statistics
- Recent activity monitoring
- Team-based analytics
- Export activity tracking

## 🔧 Development Setup

1. **Clone/Download** project files
2. **Create virtual environment**: `python -m venv .venv`
3. **Activate environment**: `.venv\Scripts\activate` (Windows)
4. **Install dependencies**: `pip install -r requirements.txt`
5. **Run application**: `python app.py`
6. **Access application**: `http://127.0.0.1:5000`

## 🚀 Production Deployment

1. **Update configuration**: Set production secret key
2. **Database setup**: Configure PostgreSQL
3. **Environment variables**: Set all production values
4. **Security**: Enable HTTPS, secure cookies
5. **WSGI server**: Use Gunicorn or uWSGI
6. **Reverse proxy**: Configure Nginx
7. **SSL certificate**: Set up HTTPS

---

**This project demonstrates a complete, production-ready Flask application with modern web development practices and comprehensive feature set.** 🎯
