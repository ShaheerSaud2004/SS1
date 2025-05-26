import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = 'users.db'
email = 'test@test'
password = 'test'  # Not secure! For dev only.
hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
try:
    c.execute('INSERT INTO users (email, password, netid, is_admin, account_type, paid_class_count, phone) VALUES (?, ?, ?, ?, ?, ?, ?)',
              (email, hashed_pw, 'testnetid', 0, 'free', 0, '+1 (123) 456-7890'))
    conn.commit()
    print('Test user created!')
except sqlite3.IntegrityError:
    print('Test user already exists!')
finally:
    conn.close() 