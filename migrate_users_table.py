import sqlite3
import os

DB_PATH = 'users.db'

def migrate():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Add temp_password column if it doesn't exist
    try:
        c.execute('ALTER TABLE users ADD COLUMN temp_password TEXT')
        print("Added temp_password column to users table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("temp_password column already exists")
        else:
            raise e
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    migrate() 