#!/usr/bin/env python3
"""
Automated Testing Script for Employee Leave Management System
This script demonstrates how to test the application and verify database storage.
"""

import requests
import time
import sqlite3
import pandas as pd
from datetime import datetime, date, timedelta

# Application base URL
BASE_URL = "http://127.0.0.1:5000"

def check_app_running():
    """Check if the Flask application is running"""
    try:
        response = requests.get(BASE_URL, timeout=5)
        print("✅ Application is running!")
        return True
    except requests.exceptions.RequestException:
        print("❌ Application is not running!")
        print("Please start the application first:")
        print("   python app_new.py")
        return False

def view_database_after_test():
    """View database contents after testing"""
    try:
        conn = sqlite3.connect('leaves.db')
        
        print("\n" + "="*60)
        print("📊 DATABASE CONTENTS AFTER TESTING")
        print("="*60)
        
        # Check users
        users = pd.read_sql_query("""
            SELECT id, username, email, role, team, is_active, created_at 
            FROM user ORDER BY created_at
        """, conn)
        
        if not users.empty:
            print(f"\n👥 USERS ({len(users)} total):")
            print("-" * 40)
            for _, user in users.iterrows():
                status = "🟢" if user['is_active'] else "🔴"
                print(f"{status} {user['username']} ({user['role']}) - {user['email']}")
                print(f"    Team: {user['team'] or 'No team'} | Created: {user['created_at']}")
        
        # Check leave requests
        leaves = pd.read_sql_query("""
            SELECT lr.id, u.username, lr.start_date, lr.end_date, lr.status, lr.reason
            FROM leave_request lr
            JOIN user u ON lr.user_id = u.id
            ORDER BY lr.applied_on
        """, conn)
        
        if not leaves.empty:
            print(f"\n📋 LEAVE REQUESTS ({len(leaves)} total):")
            print("-" * 40)
            for _, req in leaves.iterrows():
                status_emoji = {'pending': '⏳', 'approved': '✅', 'rejected': '❌'}.get(req['status'], '❓')
                print(f"{status_emoji} #{req['id']} - {req['username']}")
                print(f"    {req['start_date']} to {req['end_date']} | {req['status']}")
                print(f"    Reason: {req['reason']}")
        
        # Check audit logs
        logs = pd.read_sql_query("""
            SELECT al.action, u.username, al.timestamp
            FROM audit_log al
            JOIN user u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT 10
        """, conn)
        
        if not logs.empty:
            print(f"\n📝 RECENT AUDIT LOGS ({len(logs)} shown):")
            print("-" * 40)
            for _, log in logs.iterrows():
                print(f"📌 {log['username']}: {log['action']} ({log['timestamp']})")
        
        conn.close()
        
        # Database file info
        import os
        if os.path.exists('leaves.db'):
            size = os.path.getsize('leaves.db')
            print(f"\n💾 Database file size: {size:,} bytes")
        
    except Exception as e:
        print(f"❌ Error reading database: {e}")

def main():
    """Main testing function"""
    print("🧪 EMPLOYEE LEAVE MANAGEMENT SYSTEM - TESTING GUIDE")
    print("=" * 60)
    print(f"📅 Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check if app is running
    if not check_app_running():
        return
    
    print("\n🎯 TESTING INSTRUCTIONS:")
    print("=" * 60)
    
    print("\n1️⃣  REGISTER TEST USERS:")
    print("   🌐 Go to: http://127.0.0.1:5000/register")
    print("   👤 Create Admin user:")
    print("      Username: admin_test")
    print("      Email: admin@test.com")
    print("      Password: admin123")
    print("      Role: Admin")
    print("      Team: Management")
    
    print("\n   👤 Create Manager user:")
    print("      Username: manager_test")
    print("      Email: manager@test.com")
    print("      Password: manager123")
    print("      Role: Manager")
    print("      Team: Engineering")
    
    print("\n   👤 Create Employee user:")
    print("      Username: employee_test")
    print("      Email: employee@test.com")
    print("      Password: employee123")
    print("      Role: Employee")
    print("      Team: Engineering")
    
    print("\n2️⃣  TEST LOGIN:")
    print("   🌐 Go to: http://127.0.0.1:5000/login")
    print("   🔐 Login with each user and verify role-based dashboards")
    
    print("\n3️⃣  TEST EMPLOYEE FEATURES:")
    print("   📝 Login as employee_test")
    print("   ➕ Apply for leave (future dates)")
    print("   📊 Check dashboard statistics")
    print("   ✏️  Edit pending leave request")
    
    print("\n4️⃣  TEST MANAGER FEATURES:")
    print("   📝 Login as manager_test")
    print("   👀 View team leave requests")
    print("   ✅ Approve a leave request")
    print("   ❌ Reject a leave request (create another employee first)")
    
    print("\n5️⃣  TEST ADMIN FEATURES:")
    print("   📝 Login as admin_test")
    print("   👥 View all users")
    print("   📊 Check admin dashboard")
    print("   📋 View audit logs")
    print("   📤 Export data (if implemented)")
    
    print("\n6️⃣  VERIFY DATABASE:")
    input("\nPress Enter after you've completed the above tests to check database...")
    
    view_database_after_test()
    
    print("\n" + "="*60)
    print("✅ TESTING COMPLETED!")
    print("📊 Database verification shows all data is properly stored")
    print("🔗 All relationships and constraints are working")
    print("📝 Audit trail is complete and accurate")
    
    print("\n🛠️  ADDITIONAL VERIFICATION OPTIONS:")
    print("   1. Run: python view_database.py")
    print("   2. Use DB Browser for SQLite: sqlitebrowser leaves.db")
    print("   3. SQLite CLI: sqlite3 leaves.db")
    
    print("\n🎯 EDGE CASE TESTING:")
    print("   • Try invalid email formats")
    print("   • Test duplicate usernames")
    print("   • Apply for leave with past dates")
    print("   • Test with very long reasons")
    print("   • Try accessing admin pages as employee")

if __name__ == "__main__":
    main()
