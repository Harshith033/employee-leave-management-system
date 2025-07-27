# 🧪 Employee Leave Management System - Complete Testing Guide

## 📋 Testing Overview
This guide will walk you through testing all features of the ELMS application and verifying database storage.

## 🚀 Getting Started

### 1. Start the Application
```bash
cd "c:\Desktop\python works\employee-Leave-MS"
python app_new.py
```
**Expected Output:**
```
✅ Database tables created successfully!
🚀 Employee Leave Management System starting...
📊 You can view the SQLite database using DB Browser for SQLite
💾 Database file: leaves.db
🌐 Access the application at: http://127.0.0.1:5000
```

### 2. Open Application in Browser
- URL: http://127.0.0.1:5000
- Should redirect to login page with Register button visible

---

## 🔐 Phase 1: User Registration & Authentication Testing

### Test 1.1: Admin User Registration
1. **Go to**: http://127.0.0.1:5000/register
2. **Fill the form:**
   - Username: `admin_user`
   - Email: `admin@company.com`
   - Password: `admin123`
   - Confirm Password: `admin123`
   - Role: `Admin`
   - Team: `Management`
3. **Click**: Register
4. **Expected**: Success message + redirect to login page

### Test 1.2: Manager User Registration
1. **Register another user:**
   - Username: `manager_john`
   - Email: `john@company.com`
   - Password: `manager123`
   - Role: `Manager`
   - Team: `IT Department`

### Test 1.3: Employee User Registration
1. **Register third user:**
   - Username: `employee_alice`
   - Email: `alice@company.com`
   - Password: `employee123`
   - Role: `Employee`
   - Team: `IT Department`

### Test 1.4: Login Testing
1. **Login as Admin**: `admin_user` / `admin123`
   - Should redirect to Admin Dashboard
2. **Logout and Login as Manager**: `manager_john` / `manager123`
   - Should redirect to Manager Dashboard
3. **Logout and Login as Employee**: `employee_alice` / `employee123`
   - Should redirect to Employee Dashboard

---

## 💼 Phase 2: Employee Features Testing

### Test 2.1: Apply for Leave (Employee)
1. **Login as**: `employee_alice`
2. **Navigate to**: Apply Leave (from dashboard or navigation)
3. **Fill leave request:**
   - Start Date: `2025-08-01`
   - End Date: `2025-08-05`
   - Reason: `Family vacation planned for summer holidays`
4. **Submit**: Should see success message and redirect to dashboard
5. **Verify**: Request appears in "My Leave Requests" with status "Pending"

### Test 2.2: Apply Multiple Leave Requests
1. **Apply another leave:**
   - Start Date: `2025-09-15`
   - End Date: `2025-09-16`
   - Reason: `Medical appointment and recovery`
2. **Apply third leave:**
   - Start Date: `2025-12-25`
   - End Date: `2025-12-31`
   - Reason: `Christmas and New Year holidays`

### Test 2.3: Edit Pending Leave Request
1. **Click "Edit"** on first leave request
2. **Change end date** to `2025-08-06`
3. **Update reason** to `Extended family vacation`
4. **Save**: Should see update confirmation

### Test 2.4: Cancel Leave Request
1. **Click "Cancel"** on one pending request
2. **Confirm cancellation**
3. **Verify**: Request removed from list

---

## 👨‍💼 Phase 3: Manager Features Testing

### Test 3.1: Manager Dashboard
1. **Login as**: `manager_john`
2. **Dashboard should show:**
   - Pending leave requests from IT Department team
   - Filter options (Status, Employee, Date range)
   - Team statistics

### Test 3.2: Approve Leave Request
1. **Click "Decide"** on Alice's leave request
2. **Select**: "Approve"
3. **Add comment**: "Approved. Enjoy your vacation!"
4. **Submit**: Should see success message
5. **Verify**: Status changed to "Approved" in dashboard

### Test 3.3: Reject Leave Request
1. **Add another employee to IT Department team** (register new user)
2. **That employee applies for leave**
3. **Manager rejects** with reason: "Insufficient notice period"
4. **Verify**: Status shows "Rejected"

---

## 🔧 Phase 4: Admin Features Testing

### Test 4.1: Admin Dashboard
1. **Login as**: `admin_user`
2. **Should see:**
   - System-wide statistics (total users, requests, approval rates)
   - Recent activity
   - Team-wise statistics

### Test 4.2: User Management
1. **Navigate to**: Users section
2. **View all registered users**
3. **Add new user** using "Add User" button
4. **Deactivate a user** (test soft delete)

### Test 4.3: Audit Logs
1. **Navigate to**: Audit Logs
2. **Verify all activities are logged:**
   - User registrations
   - Login/logout events
   - Leave applications
   - Approval/rejection decisions

### Test 4.4: Export Data
1. **Navigate to**: Reports section
2. **Export CSV** with different filters
3. **Verify**: CSV file downloads with correct data

---

## 📊 Database Verification Guide

### Method 1: Using DB Browser for SQLite (Recommended)

#### Installation:
1. **Download**: https://sqlitebrowser.org/dl/
2. **Install**: DB Browser for SQLite

#### Usage:
1. **Open DB Browser**
2. **Open Database**: `c:\Desktop\python works\employee-Leave-MS\leaves.db`
3. **Browse Data tab**: View all tables and data

#### Tables to Check:
- **user**: All registered users with roles and teams
- **leave_request**: All leave applications with status
- **audit_log**: All system activities with timestamps

### Method 2: Python Script to View Database

```python
import sqlite3
import pandas as pd

# Connect to database
conn = sqlite3.connect('leaves.db')

# View all users
print("=== USERS ===")
users = pd.read_sql_query("SELECT * FROM user", conn)
print(users)

# View all leave requests
print("\n=== LEAVE REQUESTS ===")
leaves = pd.read_sql_query("""
    SELECT lr.*, u.username as employee_name 
    FROM leave_request lr 
    JOIN user u ON lr.user_id = u.id
""", conn)
print(leaves)

# View audit logs
print("\n=== AUDIT LOGS ===")
logs = pd.read_sql_query("""
    SELECT al.*, u.username 
    FROM audit_log al 
    JOIN user u ON al.user_id = u.id 
    ORDER BY al.timestamp DESC 
    LIMIT 10
""", conn)
print(logs)

conn.close()
```

### Method 3: Built-in Database Viewer (via Terminal)

```bash
# Open SQLite command line
sqlite3 leaves.db

# View table structure
.schema

# View all users
SELECT * FROM user;

# View leave requests with employee names
SELECT lr.id, u.username, lr.start_date, lr.end_date, lr.status, lr.reason 
FROM leave_request lr 
JOIN user u ON lr.user_id = u.id;

# View recent audit logs
SELECT al.action, u.username, al.timestamp, al.ip_address 
FROM audit_log al 
JOIN user u ON al.user_id = u.id 
ORDER BY al.timestamp DESC 
LIMIT 5;

# Exit
.quit
```

---

## ✅ Verification Checklist

### User Registration Verification:
- [ ] Users created in `user` table
- [ ] Passwords are hashed (not plain text)
- [ ] Roles assigned correctly
- [ ] Created timestamps populated

### Leave Request Verification:
- [ ] Requests stored in `leave_request` table
- [ ] User IDs linked correctly
- [ ] Dates and reasons saved properly
- [ ] Status defaults to 'pending'

### Authentication Verification:
- [ ] Login creates audit log entries
- [ ] Last login timestamp updated
- [ ] IP addresses logged correctly

### Workflow Verification:
- [ ] Manager decisions update request status
- [ ] Manager ID recorded for decisions
- [ ] Decision timestamps saved
- [ ] All actions create audit logs

---

## 🐛 Common Issues & Solutions

### Issue 1: Database not found
**Solution**: Ensure you're in the correct directory when running the app

### Issue 2: Permission errors
**Solution**: Run terminal as administrator if needed

### Issue 3: Data not appearing
**Solution**: Refresh browser and check for JavaScript errors

### Issue 4: Login failures
**Solution**: Verify email-validator is installed: `pip install email-validator`

---

## 📈 Performance Testing

### Load Testing:
1. **Create 50+ users** with different roles
2. **Submit 100+ leave requests**
3. **Test concurrent access** (multiple browser tabs)
4. **Verify response times** remain acceptable

### Data Integrity Testing:
1. **Verify foreign key relationships**
2. **Test cascading deletes** (user deactivation)
3. **Check data consistency** across tables

---

## 📝 Test Results Documentation

Create a test results log:
```
Test Date: [Date]
Tester: [Name]
Version: 1.0

Phase 1 Results:
✅ User Registration: PASS
✅ Login/Logout: PASS
❌ Email Validation: FAIL (if any issues)

Phase 2 Results:
✅ Leave Application: PASS
✅ Leave Editing: PASS
✅ Leave Cancellation: PASS

Phase 3 Results:
✅ Manager Approval: PASS
✅ Manager Rejection: PASS

Phase 4 Results:
✅ Admin Dashboard: PASS
✅ User Management: PASS
✅ Audit Logs: PASS
✅ Data Export: PASS

Database Verification:
✅ All data properly stored
✅ Relationships maintained
✅ Audit trail complete
```

---

## 🎯 Next Steps After Testing

1. **Document any bugs found**
2. **Test edge cases** (invalid dates, duplicate usernames)
3. **Verify security** (SQL injection prevention, XSS protection)
4. **Test mobile responsiveness**
5. **Performance optimization** if needed

Happy Testing! 🚀
