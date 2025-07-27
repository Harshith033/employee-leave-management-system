# 🧪 Complete Testing Instructions for Employee Leave Management System

## 🚀 Quick Start Testing

### Step 1: Register Users (Start Here!)
1. **Go to**: http://127.0.0.1:5000/register
2. **Register an Admin user first:**
   - Username: `admin`
   - Email: `admin@company.com`
   - Password: `admin123`
   - Role: `Admin`
   - Team: `Management`
   - Click "Register"

3. **Register a Manager:**
   - Username: `manager`
   - Email: `manager@company.com`
   - Password: `manager123`
   - Role: `Manager`
   - Team: `IT`

4. **Register an Employee:**
   - Username: `employee`
   - Email: `employee@company.com`
   - Password: `employee123`
   - Role: `Employee`
   - Team: `IT`

### Step 2: Test Employee Workflow
1. **Login as Employee**: `employee` / `employee123`
2. **Apply for Leave**:
   - Start Date: 2025-08-01
   - End Date: 2025-08-03
   - Reason: "Summer vacation"
   - Submit request
3. **Verify**: Request appears in dashboard as "Pending"

### Step 3: Test Manager Workflow
1. **Logout and Login as Manager**: `manager` / `manager123`
2. **View Dashboard**: Should see employee's leave request
3. **Approve Request**: Click "Decide" → Select "Approve" → Add comment → Submit
4. **Verify**: Status changes to "Approved"

### Step 4: Test Admin Features
1. **Login as Admin**: `admin` / `admin123`
2. **Check Dashboard**: View system statistics
3. **Manage Users**: Go to Users section
4. **View Audit Logs**: See all activities logged

## 📊 Database Verification Methods

### Method 1: Using Python Script
```bash
cd "c:\Desktop\python works\employee-Leave-MS"
python view_database.py
```

### Method 2: Using DB Browser for SQLite
1. **Download**: https://sqlitebrowser.org/
2. **Install** DB Browser for SQLite
3. **Open**: `c:\Desktop\python works\employee-Leave-MS\leaves.db`
4. **Browse Data**: Click "Browse Data" tab

### Method 3: Using SQLite Command Line
```bash
cd "c:\Desktop\python works\employee-Leave-MS"
sqlite3 leaves.db
.tables
SELECT * FROM user;
SELECT * FROM leave_request;
SELECT * FROM audit_log;
.quit
```

## ✅ What to Verify in Database

### Users Table:
- ✅ Usernames stored correctly
- ✅ Passwords are hashed (not plain text)
- ✅ Roles assigned properly
- ✅ Teams linked correctly
- ✅ Creation timestamps populated

### Leave_Request Table:
- ✅ Employee ID linked correctly
- ✅ Start/end dates saved properly
- ✅ Status defaults to 'pending'
- ✅ Manager decisions update status
- ✅ Decision timestamps recorded

### Audit_Log Table:
- ✅ All actions logged with timestamps
- ✅ User IDs linked correctly
- ✅ IP addresses captured
- ✅ Activity details stored

## 🔧 Testing Features

### Authentication Testing:
- ✅ Registration with all roles
- ✅ Login/logout functionality
- ✅ Role-based dashboard redirection
- ✅ Access control (employees can't access admin features)

### Leave Management Testing:
- ✅ Apply for leave (employee)
- ✅ Edit pending requests (employee)
- ✅ Cancel requests (employee)
- ✅ Approve/reject requests (manager)
- ✅ View team requests (manager)
- ✅ System-wide view (admin)

### Data Integrity Testing:
- ✅ Foreign key relationships maintained
- ✅ Data validation working
- ✅ Error handling functioning
- ✅ Audit trail complete

## 🐛 If You Encounter Issues

### Issue: "AmbiguousForeignKeysError"
**Status**: ✅ FIXED - Explicit join conditions added

### Issue: Database not found
**Solution**: Register at least one user first

### Issue: Login errors
**Solution**: Ensure email-validator is installed: `pip install email-validator`

### Issue: Access denied
**Solution**: Make sure you're logged in with correct role permissions

## 📈 Expected Database Content After Testing

After following the testing steps, your database should contain:

**Users Table:**
```
ID | Username | Email              | Role     | Team       | Active
1  | admin    | admin@company.com  | admin    | Management | 1
2  | manager  | manager@company.com| manager  | IT         | 1  
3  | employee | employee@company.com| employee| IT         | 1
```

**Leave_Request Table:**
```
ID | User_ID | Start_Date | End_Date   | Status   | Manager_ID | Reason
1  | 3       | 2025-08-01 | 2025-08-03 | approved | 2          | Summer vacation
```

**Audit_Log Table:**
```
ID | User_ID | Action              | Timestamp           | IP_Address
1  | 1       | User logged in      | 2025-07-27 18:30:00 | 127.0.0.1
2  | 3       | Applied for leave   | 2025-07-27 18:31:00 | 127.0.0.1
3  | 2       | Approved leave #1   | 2025-07-27 18:32:00 | 127.0.0.1
```

## 🎯 Success Criteria

Your application is working correctly if:
- ✅ All users can register and login
- ✅ Role-based dashboards display correctly
- ✅ Leave requests flow from employee → manager → approval
- ✅ All actions are logged in audit_log table
- ✅ Database relationships are maintained
- ✅ No foreign key errors occur

Start testing now at: http://127.0.0.1:5000/register 🚀
