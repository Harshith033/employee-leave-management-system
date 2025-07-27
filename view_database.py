#!/usr/bin/env python3
"""
Database Viewer for Employee Leave Management System
This script helps you view and verify data stored in the SQLite database.
"""

import sqlite3
import pandas as pd
from datetime import datetime
import os

def connect_database():
    """Connect to the SQLite database"""
    db_path = 'leaves.db'
    if not os.path.exists(db_path):
        print("❌ Database file 'leaves.db' not found!")
        print("Make sure you're running this from the correct directory.")
        return None
    
    try:
        conn = sqlite3.connect(db_path)
        print("✅ Connected to database successfully!")
        return conn
    except Exception as e:
        print(f"❌ Error connecting to database: {e}")
        return None

def view_users(conn):
    """Display all users in the system"""
    print("\n" + "="*60)
    print("👥 USERS TABLE")
    print("="*60)
    
    query = """
    SELECT 
        id,
        username,
        email,
        role,
        team,
        is_active,
        created_at,
        last_login
    FROM user 
    ORDER BY created_at DESC
    """
    
    try:
        df = pd.read_sql_query(query, conn)
        if df.empty:
            print("No users found in database.")
        else:
            print(f"Total Users: {len(df)}")
            print("-" * 60)
            for _, user in df.iterrows():
                status = "🟢 Active" if user['is_active'] else "🔴 Inactive"
                print(f"ID: {user['id']} | {user['username']} ({user['role']}) | {status}")
                print(f"   Email: {user['email']}")
                print(f"   Team: {user['team'] or 'No team'}")
                print(f"   Created: {user['created_at']}")
                print(f"   Last Login: {user['last_login'] or 'Never'}")
                print("-" * 60)
    except Exception as e:
        print(f"Error viewing users: {e}")

def view_leave_requests(conn):
    """Display all leave requests"""
    print("\n" + "="*60)
    print("📋 LEAVE REQUESTS TABLE")
    print("="*60)
    
    query = """
    SELECT 
        lr.id,
        u.username as employee,
        u.team,
        lr.start_date,
        lr.end_date,
        lr.reason,
        lr.status,
        m.username as manager,
        lr.decision_reason,
        lr.applied_on,
        lr.decided_at
    FROM leave_request lr
    JOIN user u ON lr.user_id = u.id
    LEFT JOIN user m ON lr.manager_id = m.id
    ORDER BY lr.applied_on DESC
    """
    
    try:
        df = pd.read_sql_query(query, conn)
        if df.empty:
            print("No leave requests found in database.")
        else:
            print(f"Total Leave Requests: {len(df)}")
            print("-" * 60)
            for _, req in df.iterrows():
                # Calculate days
                start = pd.to_datetime(req['start_date'])
                end = pd.to_datetime(req['end_date'])
                days = (end - start).days + 1
                
                # Status emoji
                status_emoji = {
                    'pending': '⏳',
                    'approved': '✅',
                    'rejected': '❌'
                }.get(req['status'].lower(), '❓')
                
                print(f"Request #{req['id']} | {status_emoji} {req['status'].upper()}")
                print(f"   Employee: {req['employee']} ({req['team']})")
                print(f"   Dates: {req['start_date']} to {req['end_date']} ({days} days)")
                print(f"   Reason: {req['reason']}")
                print(f"   Applied: {req['applied_on']}")
                
                if req['manager']:
                    print(f"   Decided by: {req['manager']} on {req['decided_at']}")
                    if req['decision_reason']:
                        print(f"   Comment: {req['decision_reason']}")
                
                print("-" * 60)
    except Exception as e:
        print(f"Error viewing leave requests: {e}")

def view_audit_logs(conn, limit=20):
    """Display recent audit logs"""
    print("\n" + "="*60)
    print(f"📊 AUDIT LOGS (Last {limit} entries)")
    print("="*60)
    
    query = """
    SELECT 
        al.id,
        u.username,
        al.action,
        al.timestamp,
        al.ip_address,
        al.details
    FROM audit_log al
    JOIN user u ON al.user_id = u.id
    ORDER BY al.timestamp DESC
    LIMIT ?
    """
    
    try:
        df = pd.read_sql_query(query, conn, params=(limit,))
        if df.empty:
            print("No audit logs found in database.")
        else:
            print(f"Showing {len(df)} most recent entries:")
            print("-" * 60)
            for _, log in df.iterrows():
                print(f"#{log['id']} | {log['username']} | {log['timestamp']}")
                print(f"   Action: {log['action']}")
                print(f"   IP: {log['ip_address']}")
                if log['details']:
                    print(f"   Details: {log['details']}")
                print("-" * 60)
    except Exception as e:
        print(f"Error viewing audit logs: {e}")

def database_statistics(conn):
    """Show database statistics"""
    print("\n" + "="*60)
    print("📈 DATABASE STATISTICS")
    print("="*60)
    
    try:
        # User statistics
        user_stats = pd.read_sql_query("""
            SELECT 
                role,
                COUNT(*) as count,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as active
            FROM user 
            GROUP BY role
        """, conn)
        
        print("👥 Users by Role:")
        for _, stat in user_stats.iterrows():
            print(f"   {stat['role'].title()}: {stat['active']}/{stat['count']} active")
        
        # Leave request statistics
        leave_stats = pd.read_sql_query("""
            SELECT 
                status,
                COUNT(*) as count
            FROM leave_request 
            GROUP BY status
        """, conn)
        
        print("\n📋 Leave Requests by Status:")
        for _, stat in leave_stats.iterrows():
            emoji = {'pending': '⏳', 'approved': '✅', 'rejected': '❌'}.get(stat['status'], '❓')
            print(f"   {emoji} {stat['status'].title()}: {stat['count']}")
        
        # Team statistics
        team_stats = pd.read_sql_query("""
            SELECT 
                u.team,
                COUNT(DISTINCT u.id) as users,
                COUNT(lr.id) as leave_requests
            FROM user u
            LEFT JOIN leave_request lr ON u.id = lr.user_id
            WHERE u.team IS NOT NULL
            GROUP BY u.team
        """, conn)
        
        if not team_stats.empty:
            print("\n🏢 Team Statistics:")
            for _, stat in team_stats.iterrows():
                print(f"   {stat['team']}: {stat['users']} users, {stat['leave_requests']} requests")
        
        # Recent activity
        recent_activity = pd.read_sql_query("""
            SELECT COUNT(*) as count
            FROM audit_log 
            WHERE timestamp >= datetime('now', '-24 hours')
        """, conn)
        
        print(f"\n🕐 Activity in last 24 hours: {recent_activity.iloc[0]['count']} actions")
        
    except Exception as e:
        print(f"Error generating statistics: {e}")

def export_data(conn):
    """Export all data to CSV files"""
    print("\n" + "="*60)
    print("📤 EXPORTING DATA TO CSV FILES")
    print("="*60)
    
    try:
        # Export users
        users_df = pd.read_sql_query("SELECT * FROM user", conn)
        users_df.to_csv('users_export.csv', index=False)
        print(f"✅ Users exported to 'users_export.csv' ({len(users_df)} records)")
        
        # Export leave requests
        leaves_df = pd.read_sql_query("""
            SELECT 
                lr.*,
                u.username as employee_name,
                m.username as manager_name
            FROM leave_request lr
            JOIN user u ON lr.user_id = u.id
            LEFT JOIN user m ON lr.manager_id = m.id
        """, conn)
        leaves_df.to_csv('leave_requests_export.csv', index=False)
        print(f"✅ Leave requests exported to 'leave_requests_export.csv' ({len(leaves_df)} records)")
        
        # Export audit logs
        logs_df = pd.read_sql_query("""
            SELECT 
                al.*,
                u.username
            FROM audit_log al
            JOIN user u ON al.user_id = u.id
        """, conn)
        logs_df.to_csv('audit_logs_export.csv', index=False)
        print(f"✅ Audit logs exported to 'audit_logs_export.csv' ({len(logs_df)} records)")
        
    except Exception as e:
        print(f"Error exporting data: {e}")

def main():
    """Main function to run the database viewer"""
    print("🗃️  EMPLOYEE LEAVE MANAGEMENT SYSTEM - DATABASE VIEWER")
    print("=" * 60)
    print(f"📅 Run Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Connect to database
    conn = connect_database()
    if not conn:
        return
    
    try:
        # Show all data
        database_statistics(conn)
        view_users(conn)
        view_leave_requests(conn)
        view_audit_logs(conn)
        
        # Ask if user wants to export
        print("\n" + "="*60)
        export_choice = input("Do you want to export data to CSV files? (y/n): ").lower().strip()
        if export_choice in ['y', 'yes']:
            export_data(conn)
        
        print("\n✅ Database review completed!")
        
    except Exception as e:
        print(f"❌ Error during database review: {e}")
    
    finally:
        conn.close()
        print("🔒 Database connection closed.")

if __name__ == "__main__":
    main()
