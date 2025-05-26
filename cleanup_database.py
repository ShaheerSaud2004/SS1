import sqlite3
import os

DB_PATH = 'users.db'

def cleanup_database():
    print("Starting database cleanup...")
    
    # Connect to the database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Delete all users except admin
        print("Deleting all users except admin...")
        c.execute('DELETE FROM users WHERE email != "admin@admin"')
        
        # Delete all waitlist entries
        print("Deleting all waitlist entries...")
        c.execute('DELETE FROM waitlist')
        
        # Delete all user courses
        print("Deleting all user courses...")
        c.execute('DELETE FROM user_courses')
        
        # Delete all user requests
        print("Deleting all user requests...")
        c.execute('DELETE FROM user_requests')
        
        # Delete all payments
        print("Deleting all payments...")
        c.execute('DELETE FROM payments')
        
        # Commit the changes
        conn.commit()
        print("Database cleanup completed successfully!")
        
    except Exception as e:
        print(f"Error during cleanup: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    cleanup_database() 