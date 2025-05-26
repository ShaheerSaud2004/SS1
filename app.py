from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO
import threading
import time
from advancedCourseSniper import check_course_open, ensure_logged_in, get_chrome_driver, send_email
import os
import json
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
from twilio.rest import Client as TwilioClient
import csv
from io import StringIO
import psutil
import platform
import random
import shutil
from dotenv import load_dotenv
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# Store active monitoring threads and user data
active_monitors = {}
user_data = {}

# Add this global dict at the top of app.py
active_drivers = {}
selenium_login_status = {}

load_dotenv('secret.env')  # Explicitly load from secret.env

# Email configuration
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')

if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    print("[WARNING] Email configuration missing. Email notifications will not work.")
    print("[WARNING] Please set EMAIL_ADDRESS and EMAIL_PASSWORD in your environment.")
    print(f"[DEBUG] EMAIL_ADDRESS: {EMAIL_ADDRESS}")
    print(f"[DEBUG] EMAIL_PASSWORD: {'*' * len(EMAIL_PASSWORD) if EMAIL_PASSWORD else None}")

DB_PATH = 'users.db'
stripe.api_key = os.environ.get('STRIPE_API_KEY')
STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Helper to get current user
from flask import g

# --- Twilio SMS integration ---
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_NUMBER = os.environ.get('TWILIO_NUMBER')
twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
def send_sms_alert(to_number, message):
    try:
        msg = twilio_client.messages.create(
            body=message,
            from_=TWILIO_NUMBER,
            to=to_number
        )
        print(f"[Twilio] Message sent! SID: {msg.sid}")
    except Exception as e:
        print(f"[Twilio] SMS failed: {e}")
# --- End Twilio SMS integration ---

import time
start_time = time.time()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        netid TEXT,
        is_admin INTEGER DEFAULT 0,
        last_login TEXT,
        account_type TEXT DEFAULT 'free',
        paid_class_count INTEGER DEFAULT 0,
        phone TEXT,
        phone_notifications INTEGER DEFAULT 0,
        phone_verified INTEGER DEFAULT 0,
        temp_password TEXT
    )''')
    # Ensure user_courses table exists
    c.execute('''CREATE TABLE IF NOT EXISTS user_courses (
        user_id INTEGER,
        course_index TEXT
    )''')
    # Payments table
    c.execute('''CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT,
        amount INTEGER,
        currency TEXT,
        status TEXT,
        timestamp TEXT,
        stripe_id TEXT
    )''')
    # Try to add columns if they don't exist (for migration)
    try:
        c.execute("ALTER TABLE users ADD COLUMN account_type TEXT DEFAULT 'free'")
    except Exception: pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN paid_class_count INTEGER DEFAULT 0")
    except Exception: pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    except Exception: pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN phone_notifications INTEGER DEFAULT 0")
    except Exception: pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN phone_verified INTEGER DEFAULT 0")
    except Exception: pass
    conn.commit()
    # Add default admin if not exists
    admin_email = 'admin@admin'
    admin_pw = generate_password_hash('admin', method='pbkdf2:sha256')
    c.execute('SELECT id FROM users WHERE email = ?', (admin_email,))
    if not c.fetchone():
        c.execute('INSERT INTO users (email, password, netid, is_admin, account_type, paid_class_count, phone, phone_notifications, phone_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  (admin_email, admin_pw, 'admin', 1, 'admin', 99, '1234567890', 0, 0))
        print('Default admin account created: admin@admin / admin')
    conn.commit()
    # Scheduled notifications table
    c.execute('''CREATE TABLE IF NOT EXISTS scheduled_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        notif_type TEXT,
        target TEXT,
        scheduled_time TEXT,
        sent INTEGER DEFAULT 0,
        created_at TEXT
    )''')
    conn.commit()
    # Notification templates table
    c.execute('''CREATE TABLE IF NOT EXISTS notification_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        subject TEXT,
        body TEXT,
        type TEXT
    )''')
    conn.commit()
    # Waitlist table
    c.execute('''
        CREATE TABLE IF NOT EXISTS waitlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            netid TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

print("[DEBUG] Using database at:", os.path.abspath(DB_PATH))

init_db()

def get_user_log_file(user_id):
    return f"logs/user_{user_id}.log"

def log_user_activity(user_id, message, details=None):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{user_id}] {message}\n"
    if details:
        entry += f"DETAILS: {details}\n"
    with open(get_user_log_file(user_id), "a") as f:
        f.write(entry)
    with open("logs/master.log", "a") as f:
        f.write(entry)
    # Emit real-time log event
    socketio.emit('activity_log', {'user_id': user_id, 'entry': entry})

def monitor_course(course_index, user_id):
    """Background task to monitor a course"""
    user_info = user_data[user_id]
    while course_index in active_monitors.get(user_id, {}):
        try:
            is_open = check_course_open(course_index)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if is_open == 'invalid':
                message = f'Invalid course index: {course_index}. Monitoring stopped.'
                log_user_activity(user_id, message)
                socketio.emit('course_status', {
                    'user_id': user_id,
                    'index': course_index,
                    'status': 'invalid',
                    'message': message
                })
                send_alerts(user_info, message)
                del active_monitors[user_id][course_index]
                if course_index in user_data[user_id]['course_indexes']:
                    user_data[user_id]['course_indexes'].remove(course_index)
                    user_data[user_id]['past_requests'].append({
                        'index': course_index,
                        'status': 'invalid',
                        'timestamp': now,
                        'reason': 'Invalid course index'
                    })
                break
            if is_open:
                message = f'Section {course_index} is OPEN! Attempting to register...'
                log_user_activity(user_id, message)
                socketio.emit('course_status', {
                    'user_id': user_id,
                    'index': course_index,
                    'status': 'open',
                    'message': message
                })
                
                driver = get_chrome_driver_for_user(user_id)
                try:
                    # Pass user credentials to ensure_logged_in
                    success = ensure_logged_in(driver, course_index, user_info['netid'], user_info['password'], user_id)
                    if success:
                        message = f'Successfully registered for course {course_index}!'
                        log_user_activity(user_id, message)
                        socketio.emit('course_status', {
                            'user_id': user_id,
                            'index': course_index,
                            'status': 'registered',
                            'message': message
                        })
                        send_alerts(user_info, message)
                        del active_monitors[user_id][course_index]
                        if course_index in user_data[user_id]['course_indexes']:
                            user_data[user_id]['course_indexes'].remove(course_index)
                            user_data[user_id]['past_requests'].append({
                                'index': course_index,
                                'status': 'registered',
                                'timestamp': now,
                                'reason': 'Successfully registered'
                            })
                        user_data[user_id]['last_authenticated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        message = f'Registration failed for course {course_index}. Will retry.'
                        log_user_activity(user_id, message)
                        socketio.emit('course_status', {
                            'user_id': user_id,
                            'index': course_index,
                            'status': 'failed',
                            'message': message
                        })
                        send_alerts(user_info, message)
                finally:
                    driver.quit()
            else:
                message = f'Section {course_index} is CLOSED or FULL.'
                socketio.emit('course_status', {
                    'user_id': user_id,
                    'index': course_index,
                    'status': 'closed',
                    'message': message
                })
            
            time.sleep(5)  # Check every 5 seconds
        except Exception as e:
            message = f'Error monitoring course {course_index}: {str(e)}'
            log_user_activity(user_id, message)
            socketio.emit('course_status', {
                'user_id': user_id,
                'index': course_index,
                'status': 'error',
                'message': message
            })
            time.sleep(5)

@app.route('/')
def index():
    return render_template('index_copy.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        netid = request.form.get('netid', '').strip()
        phone = request.form.get('phone', '').strip()
        # Password requirements
        if len(password) < 8 or not any(c.isdigit() for c in password) or not any(c.isupper() for c in password) or password != password2:
            print("[DEBUG] Registration failed: Password requirements not met or passwords do not match.")
            return render_template('register.html', error='Password requirements not met or passwords do not match.')
        if not session.get('email_verified') or request.form.get('email') != session.get('email_to_verify'):
            print(f"[DEBUG] Registration failed: Email not verified or does not match. session.get('email_verified')={session.get('email_verified')}, request.form.get('email')={request.form.get('email')}, session.get('email_to_verify')={session.get('email_to_verify')}")
            return render_template('register.html', error='Please verify your email before registering.')
        # Check for duplicate email or netid
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            print(f"[DEBUG] Registration failed: Duplicate email {email}")
            conn.close()
            return render_template('register.html', error='An account with this email already exists.')
        c.execute('SELECT id FROM users WHERE netid = ?', (netid,))
        if c.fetchone():
            print(f"[DEBUG] Registration failed: Duplicate NetID {netid}")
            conn.close()
            return render_template('register.html', error='An account with this NetID already exists.')
        # Create user
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        is_admin = 1 if email == 'shaheersaud2004@gmail.com' else 0
        c.execute('INSERT INTO users (email, password, netid, is_admin, account_type, paid_class_count, phone) VALUES (?, ?, ?, ?, ?, ?, ?)',
                  (email, hashed_pw, netid, is_admin, 'free', 0, phone))
        conn.commit()
        print(f"[DEBUG] Inserted user {email} and committed to DB")
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify_email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    code = data.get('code', '').strip()
    
    if not email or not code:
        return jsonify({'error': 'Email and code are required'}), 400
    
    stored_code = session.get('email_code')
    stored_email = session.get('email_to_verify')
    if not stored_code or stored_code != code or stored_email != email:
        return jsonify({'error': 'Invalid verification code'}), 400
    
    session['email_verified'] = True
    return jsonify({'message': 'Email verified successfully'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        print(f"[DEBUG] Login attempt for email: {email}")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, password, netid, is_admin, account_type, paid_class_count, phone, phone_notifications, phone_verified, temp_password FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        print(f"[DEBUG] User from DB: {user}")
        conn.close()
        
        if user:
            print(f"[DEBUG] Stored password hash: {user[1]}")
            if check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['email'] = email
                session['netid'] = user[2]
                session['is_admin'] = bool(user[3])
                
                # Check if user has a temporary password
                if user[9]:  # temp_password is not None
                    # Only force password change if they're using the temporary password
                    if password == user[9]:
                        session['force_password_change'] = True
                        return redirect(url_for('change_password'))
                
                # Update last_login
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                         (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user[0]))
                
                # Load courses and requests
                c.execute('SELECT course_index FROM user_courses WHERE user_id = ?', (user[0],))
                courses = [row[0] for row in c.fetchall()]
                c.execute('SELECT course_index, status, timestamp, reason FROM user_requests WHERE user_id = ?', (user[0],))
                requests = [
                    {'index': row[0], 'status': row[1], 'timestamp': row[2], 'reason': row[3]} 
                    for row in c.fetchall()
                ]
                conn.commit()
                conn.close()
                
                user_data[user[0]] = {
                    'email': email,
                    'netid': user[2],
                    'password': '',
                    'course_indexes': courses,
                    'past_requests': requests,
                    'account_type': user[4],
                    'paid_class_count': user[5],
                    'last_ip': request.remote_addr,
                    'phone': user[6] if len(user) > 6 else '',
                    'phone_notifications': bool(user[7]) if len(user) > 7 else False,
                    'phone_verified': bool(user[8]) if len(user) > 8 else False
                }
                
                if session['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard') + '?wipe=1')
            else:
                print("[DEBUG] Login failed: Invalid password")
                return render_template('login.html', error='Invalid password. Please try again.', show_error=True)
        else:
            print("[DEBUG] Login failed: User not found")
            return render_template('login.html', error='No account found with this email. Please check your email or register.', show_error=True)
    
    # If there's a message parameter, show it
    message = request.args.get('message')
    show_success = request.args.get('show_success', 'false').lower() == 'true'
    return render_template('login.html', message=message, show_success=show_success)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('user_id'):
        return redirect(url_for('login', message='Please log in first'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or not confirm_password:
            return render_template('change_password.html', error='Please fill in all fields', show_error=True)
        
        if new_password != confirm_password:
            return render_template('change_password.html', error='Passwords do not match. Please try again.', show_error=True)
        
        if len(new_password) < 8:
            return render_template('change_password.html', error='Password must be at least 8 characters long', show_error=True)
        
        if not any(c.isupper() for c in new_password):
            return render_template('change_password.html', error='Password must contain at least one uppercase letter', show_error=True)
        
        if not any(c.isdigit() for c in new_password):
            return render_template('change_password.html', error='Password must contain at least one number', show_error=True)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            # Update password and clear temporary password
            hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
            c.execute('UPDATE users SET password = ?, temp_password = NULL WHERE id = ?', 
                     (hashed_pw, session['user_id']))
            conn.commit()
            
            # Clear the force password change flag
            session.pop('force_password_change', None)
            
            # Log the user out to force them to log in with their new password
            session.clear()
            
            # Redirect to login with success message
            return redirect(url_for('login', message='Password changed successfully! Please log in with your new password.', show_success=True))
        except Exception as e:
            print(f"[ERROR] Failed to update password: {str(e)}")
            return render_template('change_password.html', error='Failed to update password. Please try again.', show_error=True)
        finally:
            conn.close()
    
    return render_template('change_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    user_info = user_data.get(user_id, {})
    
    # Read user's log file
    log_entries = []
    log_file = get_user_log_file(user_id)
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            log_entries = f.readlines()
    
    last_auth = user_data.get(user_id, {}).get('last_authenticated', None)
    return render_template('dashboard.html', 
                    user_info=user_info,
                    log_entries=log_entries[-50:],
                    past_requests=user_info.get('past_requests', []),
                    last_authenticated=last_auth)

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    print("[DEBUG] /stop_monitoring called")
    if 'user_id' not in session:
        print("[DEBUG] Not logged in")
        return jsonify({'error': 'Not logged in'}), 401
    user_id = session['user_id']
    data = request.json
    course_index = data.get('course_index')
    print(f"[DEBUG] Attempting to stop monitoring course_index={course_index} for user_id={user_id}")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    found = False
    # Remove from active_monitors if present
    if course_index in active_monitors.get(user_id, {}):
        del active_monitors[user_id][course_index]
        found = True
        print(f"[DEBUG] Removed from active_monitors: {course_index}")
    # Remove from user_data['course_indexes'] if present
    if user_id in user_data and course_index in user_data[user_id].get('course_indexes', []):
        user_data[user_id]['course_indexes'].remove(course_index)
        found = True
        print(f"[DEBUG] Removed from user_data['course_indexes']: {course_index}")
    # Remove from DB if present
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM user_courses WHERE user_id = ? AND course_index = ?', (user_id, course_index))
    if c.rowcount > 0:
        found = True
        print(f"[DEBUG] Deleted from user_courses DB: user_id={user_id}, course_index={course_index}")
    # Add to past_requests if not already present
    if user_id in user_data:
        already = any(r['index'] == course_index and r['status'] == 'stopped' for r in user_data[user_id].get('past_requests', []))
        if not already:
            user_data[user_id]['past_requests'].append({
                'index': course_index,
                'status': 'stopped',
                'timestamp': now,
                'reason': 'Stopped by user'
            })
            print(f"[DEBUG] Added to past_requests: {course_index}")
            c.execute('INSERT INTO user_requests (user_id, course_index, status, timestamp, reason) VALUES (?, ?, ?, ?, ?)', (user_id, course_index, 'stopped', now, 'Stopped by user'))
            conn.commit()
            conn.close()
    if found:
        log_user_activity(user_id, f"Stopped monitoring course {course_index}")
        print(f"[DEBUG] Successfully stopped monitoring course {course_index}")
        # Notify user when monitoring is stopped
        send_alerts(user_data.get(user_id, {}), f"Stopped monitoring course {course_index} as requested.")
        return jsonify({'message': f'Stopped monitoring course {course_index}'})
    print(f"[DEBUG] Course {course_index} not found in any data for user_id={user_id}")
    return jsonify({'error': 'Course not being monitored'}), 404

@app.route('/remonitor', methods=['POST'])
def remonitor():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user_id = session['user_id']
    data = request.json
    course_index = data.get('course_index')
    # Find and remove from past_requests
    req = next((r for r in user_data[user_id]['past_requests'] if r['index'] == course_index), None)
    if req:
        user_data[user_id]['past_requests'].remove(req)
        user_data[user_id]['course_indexes'].append(course_index)
        if user_id not in active_monitors:
            active_monitors[user_id] = {}
        active_monitors[user_id][course_index] = True
        # Update DB
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO user_courses (user_id, course_index) VALUES (?, ?)', (user_id, course_index))
        c.execute('DELETE FROM user_requests WHERE user_id = ? AND course_index = ? AND status = ?', (user_id, course_index, req['status']))
        conn.commit()
        conn.close()
        thread = threading.Thread(
            target=monitor_course,
            args=(course_index, user_id)
        )
        thread.daemon = True
        thread.start()
        log_user_activity(user_id, f"Re-monitoring course {course_index}")
        return jsonify({'message': f'Re-monitoring course {course_index}'})
    return jsonify({'error': 'Course not found in past requests'}), 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    print(f"[DEBUG] Accessing admin dashboard. Session: {dict(session)}")
    if not session.get('is_admin'):
        print("[DEBUG] Not admin or not logged in. Redirecting to login.")
        return redirect(url_for('login'))
    # Get all users and their monitoring info
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, email, netid, is_admin, last_login, account_type, paid_class_count, phone_notifications, phone_verified FROM users')
    users = c.fetchall()
    # Banned count
    try:
        c.execute('SELECT COUNT(*) FROM users WHERE banned=1')
        banned_count = c.fetchone()[0]
    except:
        banned_count = 0
    # Admin count
    c.execute('SELECT COUNT(*) FROM users WHERE is_admin=1')
    admin_count = c.fetchone()[0]
    # SMS-enabled count
    c.execute('SELECT COUNT(*) FROM users WHERE phone_notifications=1')
    sms_enabled_count = c.fetchone()[0]
    # Recent logins (last 24h)
    since = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('SELECT COUNT(*) FROM users WHERE last_login >= ?', (since,))
    recent_logins = c.fetchone()[0]
    conn.close()
    # Gather monitoring info from user_data
    all_monitoring = {}
    course_counter = {}
    for user in users:
        uid = user[0]
        all_monitoring[uid] = user_data.get(uid, {'course_indexes': [], 'past_requests': [], 'account_type': user[5], 'paid_class_count': user[6], 'last_ip': '', 'phone_verified': bool(user[8])})
        for course in all_monitoring[uid]['course_indexes']:
            course_counter[course] = course_counter.get(course, 0) + 1
    most_monitored_course = max(course_counter.items(), key=lambda x: x[1])[0] if course_counter else None
    extra_stats = {
        'admin_count': admin_count,
        'banned_count': banned_count,
        'sms_enabled_count': sms_enabled_count,
        'recent_logins': recent_logins,
        'most_monitored_course': most_monitored_course
    }
    stripe_admin_url = 'https://dashboard.stripe.com/test'
    return render_template('admin.html', users=users, all_monitoring=all_monitoring, extra_stats=extra_stats, stripe_admin_url=stripe_admin_url)

@app.route('/get_user_creds')
def get_user_creds():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    info = user_data.get(user_id, {})
    return jsonify({'netid': info.get('netid', ''), 'password': info.get('password', '')})

@app.route('/save_credentials', methods=['POST'])
def save_credentials():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    data = request.get_json()
    netid = data.get('netid', '').strip()
    password = data.get('password', '').strip()
    if not netid or not password:
        return jsonify({'error': 'Missing credentials.'}), 400
    user_data.setdefault(user_id, {})['netid'] = netid
    user_data[user_id]['password'] = password
    return jsonify({'message': 'Credentials saved.'})

def human_type(element, text):
    """Simulates human-like typing with random delays between keystrokes."""
    import random
    import time
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(0.1, 0.3))  # Random delay between keystrokes

@app.route('/trigger_selenium_login', methods=['POST'])
def trigger_selenium_login():
    if 'user_id' not in session:
        print("[DEBUG] Not logged in.")
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    info = user_data.get(user_id, {})
    netid = info.get('netid')
    password = info.get('password')
    print(f"[DEBUG] Starting Selenium login flow for user_id={user_id}, netid={netid}")
    selenium_login_status[user_id] = 'in_progress'
    def selenium_login_flow():
        import random, time
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException, NoSuchWindowException, WebDriverException
        from selenium.webdriver.common.keys import Keys

        try:
            print("[DEBUG] Creating Chrome driver...")
            driver = get_chrome_driver_for_user(user_id)
            print("[DEBUG] Chrome driver created.")
            
            url = 'https://cas.rutgers.edu/login?service=https%3A%2F%2Fsims.rutgers.edu%2Fwebreg%2Fj_spring_cas_security_check'
            print(f"[DEBUG] Navigating to: {url}")
            driver.get(url)
            log_user_activity(user_id, "Opened WebReg login page in Selenium.")
            
            # If already on chooseSemester or refresh.htm, skip to success
            if 'chooseSemester' in driver.current_url or 'refresh.htm' in driver.current_url:
                print("[DEBUG] Already on chooseSemester or refresh.htm, skipping login steps.")
                log_user_activity(user_id, "Already logged in to WebReg. Skipping login steps.")
                selenium_login_status[user_id] = 'complete'
                active_drivers[user_id] = driver
                user_data[user_id]['last_authenticated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                return

            try:
                # Wait for username field with increased timeout
                WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "username")))
                print("[DEBUG] Found username field, filling credentials...")
                log_user_activity(user_id, "Filling NetID and password in WebReg login form.")
                
                # Add random delay between actions
                time.sleep(random.uniform(1, 2))
                
                # Fill username
                username_field = driver.find_element(By.ID, "username")
                human_type(username_field, netid)
                
                time.sleep(random.uniform(0.5, 1))
                
                # Fill password
                pw_elem = driver.find_element(By.ID, "password")
                human_type(pw_elem, password)
                
                time.sleep(random.uniform(0.5, 1))
                
                # Press Enter after password
                pw_elem.send_keys(Keys.RETURN)
                print("[DEBUG] Pressed Enter after password.")
                log_user_activity(user_id, "Pressed Enter after password.")

                # Wait for Duo iframe/page with increased timeout
                try:
                    print("[DEBUG] Waiting for Duo iframe/page to appear...")
                    WebDriverWait(driver, 90).until(
                        lambda d: len(d.find_elements(By.TAG_NAME, "iframe")) > 0 or 'duo' in d.page_source.lower()
                    )
                    print("[DEBUG] Duo iframe/page detected. Waiting for user to approve on device...")
                    log_user_activity(user_id, "Duo iframe/page detected. Waiting for user to approve on device.")
                    
                    # Give user more time to approve on device
                    time.sleep(10)
                    
                except TimeoutException:
                    print("[DEBUG] Duo iframe/page not detected within timeout")
                    log_user_activity(user_id, "Duo iframe/page not detected within timeout")

                # Handle "Yes, this is my device" button with improved retry logic
                max_retries = 3
                retry_count = 0
                found = False
                
                while retry_count < max_retries and not found:
                    try:
                        # Try main document first
                        yes_button = WebDriverWait(driver, 10).until(
                            EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Yes, this is my device')]"))
                        )
                        driver.execute_script("arguments[0].click();", yes_button)
                        print("[DEBUG] Clicked 'Yes, this is my device' (main doc).")
                        log_user_activity(user_id, "Clicked 'Yes, this is my device' on Duo prompt (main doc).")
                        found = True
                        break
                    except Exception as e:
                        print(f"[DEBUG] Failed to find button in main doc: {e}")
                        
                        # Try iframes
                        iframes = driver.find_elements(By.TAG_NAME, "iframe")
                        for iframe in iframes:
                            try:
                                driver.switch_to.frame(iframe)
                                yes_button = WebDriverWait(driver, 5).until(
                                    EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Yes, this is my device')]"))
                                )
                                driver.execute_script("arguments[0].click();", yes_button)
                                print("[DEBUG] Clicked 'Yes, this is my device' (iframe).")
                                log_user_activity(user_id, "Clicked 'Yes, this is my device' on Duo prompt (iframe).")
                                found = True
                                break
                            except Exception as e:
                                print(f"[DEBUG] Failed to find button in iframe: {e}")
                            finally:
                                driver.switch_to.default_content()
                        
                        if not found:
                            retry_count += 1
                            time.sleep(5)  # Wait before retry
                
                if not found:
                    print("[DEBUG] 'Yes, this is my device' button not found after retries, continuing...")
                    log_user_activity(user_id, "'Yes, this is my device' button not found after retries, continuing.")

                # Wait for successful login with increased timeout
                try:
                    print("[DEBUG] Waiting for URL to change to chooseSemester or refresh.htm...")
                    WebDriverWait(driver, 60).until(
                        lambda d: 'chooseSemester' in d.current_url or 'refresh.htm' in d.current_url
                    )
                    print("[DEBUG] Detected chooseSemester or refresh.htm in URL, login complete.")
                    log_user_activity(user_id, "WebReg login successful. Session is now active.")
                    selenium_login_status[user_id] = 'complete'
                    active_drivers[user_id] = driver
                    user_data[user_id]['last_authenticated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                except TimeoutException:
                    print("[DEBUG] Timeout waiting for successful login")
                    log_user_activity(user_id, "Timeout waiting for successful login")
                    selenium_login_status[user_id] = 'error'
                    
            except (NoSuchWindowException, WebDriverException) as e:
                print(f"[DEBUG] Browser window error: {e}")
                log_user_activity(user_id, f"Browser window error: {e}")
                selenium_login_status[user_id] = 'error'
            except Exception as e:
                print(f"[DEBUG] Exception in selenium_login_flow: {e}")
                log_user_activity(user_id, f"Exception in selenium_login_flow: {e}")
                selenium_login_status[user_id] = 'error'
                
        except Exception as e:
            print(f"[DEBUG] Exception in selenium_login_flow (outer): {e}")
            log_user_activity(user_id, f"Exception in selenium_login_flow (outer): {e}")
            selenium_login_status[user_id] = 'error'
    import threading
    threading.Thread(target=selenium_login_flow, daemon=True).start()
    return jsonify({'message': 'Login started.'})

@app.route('/check_selenium_login_status')
def check_selenium_login_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    # Check if driver is alive
    driver = active_drivers.get(user_id)
    if driver:
        try:
            _ = driver.title  # This will throw if driver is dead
            return jsonify({'status': 'complete'})
        except Exception:
            active_drivers.pop(user_id, None)
            selenium_login_status[user_id] = 'not_started'
            return jsonify({'status': 'not_started'})
    # Fallback to status flag
    status = selenium_login_status.get(user_id, 'not_started')
    return jsonify({'status': status})

@app.route('/add_courses', methods=['POST'])
def add_courses():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    user_info = user_data.get(user_id, {})
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT account_type, paid_class_count FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    account_type = row[0] if row else 'free'
    paid_class_count = row[1] if row else 0
    current_count = len(user_info.get('course_indexes', []))
    if account_type == 'free' and current_count >= 1:
        return jsonify({'error': 'Free accounts can only monitor one class. Upgrade to add more.'}), 403
    if account_type == 'paid' and current_count >= paid_class_count:
        return jsonify({'error': 'You have reached your paid class limit. Buy more slots to add more classes.'}), 403
    # Check for active Selenium session
    driver = active_drivers.get(user_id)
    if not driver:
        return jsonify({'error': 'Rutgers login required.'}), 428
    try:
        _ = driver.title
    except Exception:
        active_drivers.pop(user_id, None)
        return jsonify({'error': 'Rutgers login required.'}), 428
    # Ensure user_data and active_monitors are initialized
    if user_id not in user_data:
        user_data[user_id] = {
            'email': session.get('email', ''),
            'netid': session.get('netid', ''),
            'password': '',
            'course_indexes': [],
            'past_requests': []
        }
    if user_id not in active_monitors:
        active_monitors[user_id] = {}
    indexes = request.form.get('course_indexes', '')
    indexes = [idx.strip() for idx in indexes.split(',') if idx.strip()]
    if not indexes:
        return jsonify({'error': 'No course indexes provided'}), 400
    # Add to user's course_indexes and start monitoring
    for course_index in indexes:
        if course_index not in user_data[user_id]['course_indexes']:
            user_data[user_id]['course_indexes'].append(course_index)
            active_monitors[user_id][course_index] = True
            c.execute('INSERT OR IGNORE INTO user_courses (user_id, course_index) VALUES (?, ?)', (user_id, course_index))
            thread = threading.Thread(
                target=monitor_course,
                args=(course_index, user_id)
            )
            thread.daemon = True
            thread.start()
            # Send notification when monitoring starts
            send_alerts(user_data[user_id], f"Monitoring started for course {course_index}. You'll be notified if a spot opens up.")
    conn.commit()
    conn.close()
    return jsonify({'message': 'Monitoring started for new courses'})

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403
    user_id = request.form.get('user_id')
    if not user_id or int(user_id) == session['user_id']:
        return jsonify({'error': 'Invalid user'}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    user_data.pop(int(user_id), None)
    active_monitors.pop(int(user_id), None)
    return jsonify({'message': 'User deleted'})

# Helper to get current user
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, email FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {'id': row[0], 'email': row[1]}
    return None

@app.route('/buy_slot', methods=['POST'])
def buy_slot():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {
                    'name': 'ScarletSniper Class Slot',
                },
                'unit_amount': 500,
            },
            'quantity': 1,
        }],
        mode='payment',
        customer_email=user['email'],
        success_url=request.host_url + 'dashboard?payment=success',
        cancel_url=request.host_url + 'dashboard?payment=cancel',
        metadata={'user_id': user['id']}
    )
    return jsonify({'checkout_url': session.url})

from flask import request
import json

@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    endpoint_secret = STRIPE_WEBHOOK_SECRET
    event = None
    try:
        if endpoint_secret:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        else:
            event = json.loads(payload)
    except Exception as e:
        return str(e), 400
    # Handle successful payment
    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        user_id = session_obj['metadata'].get('user_id')
        amount = session_obj.get('amount_total', 0)
        currency = session_obj.get('currency', 'usd')
        email = session_obj.get('customer_email', '')
        stripe_id = session_obj.get('id', '')
        status = session_obj.get('payment_status', 'unknown')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if user_id:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('UPDATE users SET account_type = ?, paid_class_count = paid_class_count + 1 WHERE id = ?', ('paid', user_id))
            c.execute('SELECT email, paid_class_count FROM users WHERE id = ?', (user_id,))
            row = c.fetchone()
            # Insert payment record
            c.execute('INSERT INTO payments (user_id, email, amount, currency, status, timestamp, stripe_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                      (user_id, email, amount, currency, status, timestamp, stripe_id))
            conn.commit()
            conn.close()
            if row:
                email, slot_count = row
                send_alerts(user_data.get(user_id, {}), f"Thank you for your payment! You now have {slot_count} class slot(s) available to monitor/register.")
    return '', 200

@app.route('/get_slot_info')
def get_slot_info():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT account_type, paid_class_count FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    account_type = row[0] if row else 'free'
    paid_class_count = row[1] if row else 0
    current_count = len(user_data.get(user_id, {}).get('course_indexes', []))
    max_count = 1 if account_type == 'free' else paid_class_count
    return jsonify({
        'account_type': account_type,
        'current_count': current_count,
        'max_count': max_count
    })

@app.route('/logout_webreg', methods=['POST'])
def logout_webreg():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    driver = active_drivers.pop(user_id, None)
    if driver:
        try:
            driver.quit()
        except Exception:
            pass
    user_data[user_id]['last_authenticated'] = None
    return jsonify({'message': 'WebReg session logged out.'})

@app.route('/get_activity_log')
def get_activity_log():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in.'}), 401
    user_id = session['user_id']
    log_file = get_user_log_file(user_id)
    if not os.path.exists(log_file):
        return jsonify({'entries': []})
    with open(log_file, 'r') as f:
        lines = f.readlines()[-100:]
    return jsonify({'entries': lines})

@app.route('/admin/logs')
def admin_logs():
    if not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403
    log_file = "logs/master.log"
    if not os.path.exists(log_file):
        return jsonify({'entries': []})
    with open(log_file, 'r') as f:
        lines = f.readlines()[-1000:]
    return jsonify({'entries': lines})

# Professional email/SMS template
EMAIL_SMS_TEMPLATE = '''
Dear {name},

{message}

If you have any questions or need assistance, please reply to this message.

Thank you for using ScarletSniper. We're here to help you succeed!

Best regards,
The ScarletSniper Team
'''

def send_alerts(user_info, message):
    # Send email only
    send_email(
        "ScarletSniper Notification: Course Registration Update",
        EMAIL_SMS_TEMPLATE.format(name=user_info.get('netid', 'Student'), message=message),
        user_info['email']
    )

@app.route('/toggle_sms', methods=['POST'])
def toggle_sms():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    phone = request.form.get('phone', '').strip()
    phone_notifications = 1 if request.form.get('phone_notifications') == 'on' else 0
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET phone = ?, phone_notifications = ? WHERE id = ?', (phone, phone_notifications, user_id))
    conn.commit()
    conn.close()
    # Update in-memory user_data
    if user_id in user_data:
        user_data[user_id]['phone'] = phone
        user_data[user_id]['phone_notifications'] = bool(phone_notifications)
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_user', methods=['POST'])
def admin_edit_user():
    if not session.get('is_admin'): 
        return {'error': 'Not authorized'}, 403
    
    data = request.json
    user_id = data.get('user_id')
    email = data.get('email')
    phone = data.get('phone')
    account_type = data.get('account_type')
    paid_class_count = int(data.get('paid_class_count', 0))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Get current user data
        c.execute('SELECT account_type, paid_class_count FROM users WHERE id = ?', (user_id,))
        current_data = c.fetchone()
        if not current_data:
            return {'error': 'User not found'}, 404
        
        current_type, current_slots = current_data
        
        # Update user data
        c.execute('UPDATE users SET email=?, phone=?, account_type=?, paid_class_count=? WHERE id=?', 
                 (email, phone, account_type, paid_class_count, user_id))
        
        # If changing from free to paid, ensure paid_class_count is at least 1
        if current_type == 'free' and account_type == 'paid' and paid_class_count < 1:
            paid_class_count = 1
            c.execute('UPDATE users SET paid_class_count = 1 WHERE id = ?', (user_id,))
        
        # If changing from paid to free, ensure they don't exceed free account limits
        if current_type == 'paid' and account_type == 'free':
            # Get current number of monitored courses
            current_monitors = len(user_data.get(user_id, {}).get('course_indexes', []))
            if current_monitors > 1:
                # Remove excess monitors, keeping only the first one
                user_data[user_id]['course_indexes'] = user_data[user_id]['course_indexes'][:1]
                # Update database
                c.execute('DELETE FROM user_courses WHERE user_id = ? AND course_index NOT IN (SELECT course_index FROM user_courses WHERE user_id = ? LIMIT 1)', 
                         (user_id, user_id))
        
        conn.commit()
        
        # Update user_data in memory
        # --- RELOAD user data from DB so dashboard is always up to date ---
        c.execute('SELECT id, email, netid, is_admin, last_login, account_type, paid_class_count, phone, phone_notifications, phone_verified FROM users WHERE id = ?', (user_id,))
        row = c.fetchone()
        if row:
            # Load courses and requests
            c2 = sqlite3.connect(DB_PATH)
            c2_cur = c2.cursor()
            c2_cur.execute('SELECT course_index FROM user_courses WHERE user_id = ?', (user_id,))
            courses = [r[0] for r in c2_cur.fetchall()]
            # If you have a user_requests table, load past requests
            try:
                c2_cur.execute('SELECT course_index, status, timestamp, reason FROM user_requests WHERE user_id = ?', (user_id,))
                requests = [
                    {'index': r[0], 'status': r[1], 'timestamp': r[2], 'reason': r[3]} for r in c2_cur.fetchall()
                ]
            except Exception:
                requests = []
            c2.close()
            user_data[int(user_id)] = {
                'email': row[1],
                'netid': row[2],
                'password': '',
                'course_indexes': courses,
                'past_requests': requests,
                'account_type': row[5],
                'paid_class_count': row[6],
                'last_ip': '',
                'phone': row[7] if len(row) > 7 else '',
                'phone_notifications': bool(row[8]) if len(row) > 8 else False,
                'phone_verified': bool(row[9]) if len(row) > 9 else False
            }
        
        # Notify user of changes
        if int(user_id) in user_data:
            user_info = user_data[int(user_id)]
            if current_type != account_type:
                message = f"Your account has been changed to {account_type}. "
                if account_type == 'free':
                    message += "You can now monitor up to 1 course."
                else:
                    message += f"You can now monitor up to {paid_class_count} courses."
                send_alerts(user_info, message)
            elif current_slots != paid_class_count and account_type == 'paid':
                send_alerts(user_info, f"Your paid account slot limit has been updated to {paid_class_count} courses.")
        
        return {'message': 'User updated successfully'}
    
    except Exception as e:
        conn.rollback()
        return {'error': f'Failed to update user: {str(e)}'}, 500
    
    finally:
        conn.close()

@app.route('/admin/reset_password', methods=['POST'])
def admin_reset_password():
    if not session.get('is_admin'): return {'error': 'Not authorized'}, 403
    data = request.json
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET password=? WHERE id=?', (hashed_pw, user_id))
    conn.commit()
    conn.close()
    return {'message': 'Password reset'}

@app.route('/admin/impersonate_user', methods=['POST'])
def admin_impersonate_user():
    if not session.get('is_admin'): return {'error': 'Not authorized'}, 403
    data = request.json
    user_id = data.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT email, netid, is_admin FROM users WHERE id=?', (user_id,))
    user = c.fetchone()
    conn.close()
    if not user: return {'error': 'User not found'}, 404
    # Store original admin session for return
    session['impersonator'] = {
        'user_id': session['user_id'],
        'email': session['email'],
        'netid': session['netid'],
        'is_admin': session['is_admin']
    }
    session['user_id'] = user_id
    session['email'] = user[0]
    session['netid'] = user[1]
    session['is_admin'] = bool(user[2])
    return {'message': 'Impersonation started', 'redirect': url_for('dashboard')}

@app.route('/admin/return_to_admin')
def admin_return_to_admin():
    if 'impersonator' not in session:
        return redirect(url_for('admin_dashboard'))
    imp = session.pop('impersonator')
    session['user_id'] = imp['user_id']
    session['email'] = imp['email']
    session['netid'] = imp['netid']
    session['is_admin'] = imp['is_admin']
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/ban_user', methods=['POST'])
def admin_ban_user():
    if not session.get('is_admin'): return {'error': 'Not authorized'}, 403
    data = request.json
    user_id = data.get('user_id')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Add banned column if not exists
    try: c.execute('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0')
    except: pass
    c.execute('SELECT banned FROM users WHERE id=?', (user_id,))
    banned = c.fetchone()[0]
    new_banned = 0 if banned else 1
    c.execute('UPDATE users SET banned=? WHERE id=?', (new_banned, user_id))
    conn.commit()
    conn.close()
    return {'message': 'User banned' if new_banned else 'User unbanned', 'banned': new_banned}

@app.route('/admin/notify_user', methods=['POST'])
def admin_notify_user():
    if not session.get('is_admin'): return {'error': 'Not authorized'}, 403
    data = request.json
    user_id = data.get('user_id')
    message = data.get('message')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT email, netid, phone, phone_notifications FROM users WHERE id=?', (user_id,))
    user = c.fetchone()
    conn.close()
    if not user: return {'error': 'User not found'}, 404
    user_info = {'email': user[0], 'netid': user[1], 'phone': user[2], 'phone_notifications': bool(user[3])}
    send_alerts(user_info, message)
    return {'message': 'Notification sent'}

@app.route('/admin/data/users')
def admin_data_users():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, email, netid, is_admin, last_login, account_type, paid_class_count, phone, phone_notifications, phone_verified FROM users')
    users = [dict(zip(['id','email','netid','is_admin','last_login','account_type','paid_class_count','phone','phone_notifications','phone_verified'], row)) for row in c.fetchall()]
    conn.close()
    return {'users': users}

@app.route('/admin/data/courses')
def admin_data_courses():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    # Aggregate all monitored/requested courses
    course_counter = {}
    user_courses = {}
    for uid, info in user_data.items():
        for course in info.get('course_indexes', []):
            course_counter[course] = course_counter.get(course, 0) + 1
            user_courses.setdefault(course, []).append(uid)
        for req in info.get('past_requests', []):
            course_counter[req['index']] = course_counter.get(req['index'], 0)
            user_courses.setdefault(req['index'], [])
    courses = [{'index': k, 'monitored_by': v, 'users': user_courses[k]} for k,v in course_counter.items()]
    return {'courses': courses}

@app.route('/admin/data/monitors')
def admin_data_monitors():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    monitors = []
    for uid, info in user_data.items():
        for course in info.get('course_indexes', []):
            monitors.append({'user_id': uid, 'course_index': course})
    return {'monitors': monitors}

@app.route('/admin/data/requests')
def admin_data_requests():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    requests = []
    for uid, info in user_data.items():
        for req in info.get('past_requests', []):
            requests.append({'user_id': uid, **req})
    return {'requests': requests}

@app.route('/admin/user_timeline/<int:user_id>')
def admin_user_timeline(user_id):
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    log_file = get_user_log_file(user_id)
    if not os.path.exists(log_file):
        return {'entries': ['No activity recorded.']}
    with open(log_file, 'r') as f:
        lines = f.readlines()[-200:]
    return {'entries': lines}

@app.route('/admin/data/payments')
def admin_data_payments():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, user_id, email, amount, currency, status, timestamp, stripe_id FROM payments ORDER BY timestamp DESC')
    payments = [dict(zip(['id','user_id','email','amount','currency','status','timestamp','stripe_id'], row)) for row in c.fetchall()]
    conn.close()
    return {'payments': payments}

@app.route('/admin/export_csv/<string:datatype>')
def admin_export_csv(datatype):
    if not session.get('is_admin'):
        return 'Not authorized', 403
    si = StringIO()
    cw = csv.writer(si)
    if datatype == 'users':
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, email, netid, is_admin, last_login, account_type, paid_class_count, phone, phone_notifications, phone_verified FROM users')
        cw.writerow(['id','email','netid','is_admin','last_login','account_type','paid_class_count','phone','phone_notifications','phone_verified'])
        for row in c.fetchall():
            cw.writerow(row)
        conn.close()
    elif datatype == 'courses':
        course_counter = {}
        user_courses = {}
        for uid, info in user_data.items():
            for course in info.get('course_indexes', []):
                course_counter[course] = course_counter.get(course, 0) + 1
                user_courses.setdefault(course, []).append(uid)
            for req in info.get('past_requests', []):
                course_counter[req['index']] = course_counter.get(req['index'], 0)
                user_courses.setdefault(req['index'], [])
        cw.writerow(['index','monitored_by','user_ids'])
        for k,v in course_counter.items():
            cw.writerow([k, v, ','.join(map(str, user_courses[k]))])
    elif datatype == 'monitors':
        cw.writerow(['user_id','course_index'])
        for uid, info in user_data.items():
            for course in info.get('course_indexes', []):
                cw.writerow([uid, course])
    elif datatype == 'requests':
        cw.writerow(['user_id','index','status','timestamp','reason'])
        for uid, info in user_data.items():
            for req in info.get('past_requests', []):
                cw.writerow([uid, req['index'], req['status'], req['timestamp'], req['reason']])
    elif datatype == 'payments':
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, user_id, email, amount, currency, status, timestamp, stripe_id FROM payments ORDER BY timestamp DESC')
        cw.writerow(['id','user_id','email','amount','currency','status','timestamp','stripe_id'])
        for row in c.fetchall():
            cw.writerow(row)
        conn.close()
    else:
        return 'Invalid type', 400
    output = si.getvalue()
    return output, 200, {'Content-Type': 'text/csv', 'Content-Disposition': f'attachment; filename={datatype}.csv'}

@app.route('/admin/data/course_popularity')
def admin_data_course_popularity():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    course_counter = {}
    for uid, info in user_data.items():
        for course in info.get('course_indexes', []):
            course_counter[course] = course_counter.get(course, 0) + 1
    # Sort by popularity
    sorted_courses = sorted(course_counter.items(), key=lambda x: x[1], reverse=True)
    return {'courses': [{'index': k, 'count': v} for k, v in sorted_courses]}

@app.route('/admin/scheduled_notifications', methods=['GET', 'POST', 'DELETE'])
def admin_scheduled_notifications():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        data = request.json
        message = data.get('message')
        notif_type = data.get('notif_type', 'email')
        target = data.get('target', 'all')
        scheduled_time = data.get('scheduled_time')
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('INSERT INTO scheduled_notifications (message, notif_type, target, scheduled_time, created_at) VALUES (?, ?, ?, ?, ?)',
                  (message, notif_type, target, scheduled_time, created_at))
        conn.commit()
        conn.close()
        return {'message': 'Scheduled notification created'}
    elif request.method == 'DELETE':
        notif_id = request.args.get('id')
        c.execute('DELETE FROM scheduled_notifications WHERE id=?', (notif_id,))
        conn.commit()
        conn.close()
        return {'message': 'Deleted'}
    else:
        c.execute('SELECT id, message, notif_type, target, scheduled_time, sent, created_at FROM scheduled_notifications ORDER BY scheduled_time DESC')
        notifs = [dict(zip(['id','message','notif_type','target','scheduled_time','sent','created_at'], row)) for row in c.fetchall()]
        conn.close()
        return {'notifications': notifs}

def send_scheduled_notifications():
    while True:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('SELECT id, message, notif_type, target FROM scheduled_notifications WHERE sent=0 AND scheduled_time<=?', (now,))
        for row in c.fetchall():
            notif_id, message, notif_type, target = row
            # Send to all users or specific user
            if target == 'all':
                c2 = conn.cursor()
                c2.execute('SELECT email, netid, phone, phone_notifications FROM users')
                for u in c2.fetchall():
                    user_info = {'email': u[0], 'netid': u[1], 'phone': u[2], 'phone_notifications': bool(u[3])}
                    send_alerts(user_info, message)
            else:
                # target is user_id
                c2 = conn.cursor()
                c2.execute('SELECT email, netid, phone, phone_notifications FROM users WHERE id=?', (target,))
                u = c2.fetchone()
                if u:
                    user_info = {'email': u[0], 'netid': u[1], 'phone': u[2], 'phone_notifications': bool(u[3])}
                    send_alerts(user_info, message)
            c.execute('UPDATE scheduled_notifications SET sent=1 WHERE id=?', (notif_id,))
        conn.commit()
        conn.close()
        time.sleep(60)

threading.Thread(target=send_scheduled_notifications, daemon=True).start()

@app.route('/admin/templates', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin_templates():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        data = request.json
        c.execute('INSERT INTO notification_templates (name, subject, body, type) VALUES (?, ?, ?, ?)',
                  (data.get('name'), data.get('subject'), data.get('body'), data.get('type')))
        conn.commit()
        conn.close()
        return {'message': 'Template created'}
    elif request.method == 'PUT':
        data = request.json
        c.execute('UPDATE notification_templates SET name=?, subject=?, body=?, type=? WHERE id=?',
                  (data.get('name'), data.get('subject'), data.get('body'), data.get('type'), data.get('id')))
        conn.commit()
        conn.close()
        return {'message': 'Template updated'}
    elif request.method == 'DELETE':
        template_id = request.args.get('id')
        c.execute('DELETE FROM notification_templates WHERE id=?', (template_id,))
        conn.commit()
        conn.close()
        return {'message': 'Deleted'}
    else:
        c.execute('SELECT id, name, subject, body, type FROM notification_templates ORDER BY id DESC')
        templates = [dict(zip(['id','name','subject','body','type'], row)) for row in c.fetchall()]
        conn.close()
        return {'templates': templates}

@app.route('/admin/server_health')
def admin_server_health():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    uptime = int(time.time() - start_time)
    return {
        'cpu': cpu,
        'memory': {'used': mem.used, 'total': mem.total, 'percent': mem.percent},
        'disk': {'used': disk.used, 'total': disk.total, 'percent': disk.percent},
        'uptime': uptime,
        'platform': platform.platform()
    }

@app.route('/send_verification_email', methods=['POST'])
def send_verification_email():
    email = request.json.get('email', '').strip().lower()
    if not email or '@' not in email:
        return {'error': 'Invalid email address.'}, 400
    code = str(random.randint(100000, 999999))
    session['email_code'] = code
    session['email_to_verify'] = email
    # Send verification email
    send_email(
        "ScarletSniper Email Verification",
        f"Your ScarletSniper verification code is: {code}\n\nEnter this code to verify your email address.",
        email
    )
    return {'message': 'Verification code sent to your email.'}

def cleanup_old_profiles(max_age_hours=24):
    """Clean up Chrome profiles older than max_age_hours"""
    try:
        base_dir = os.path.abspath('.')
        current_time = time.time()
        for item in os.listdir(base_dir):
            if item.startswith('chrome_profile'):
                profile_path = os.path.join(base_dir, item)
                if os.path.isdir(profile_path):
                    # Get profile creation time
                    creation_time = os.path.getctime(profile_path)
                    age_hours = (current_time - creation_time) / 3600
                    if age_hours > max_age_hours:
                        try:
                            shutil.rmtree(profile_path)
                            print(f"[DEBUG] Cleaned up old profile: {profile_path}")
                        except Exception as e:
                            print(f"[DEBUG] Failed to clean up profile {profile_path}: {e}")
    except Exception as e:
        print(f"[DEBUG] Error in cleanup_old_profiles: {e}")

def get_active_sessions():
    sessions = []
    for user_id, driver in active_drivers.items():
        try:
            _ = driver.title
            is_active = True
        except Exception:
            active_drivers.pop(user_id, None)
            is_active = False
        
        sessions.append({
            'user_id': user_id,
            'active': is_active,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    return sessions

@app.route('/admin/sessions')
def admin_sessions():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    return {'sessions': get_active_sessions()}

@app.route('/admin/clear_session/<int:user_id>', methods=['POST'])
def admin_clear_session(user_id):
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    
    # Close and remove driver
    driver = active_drivers.pop(user_id, None)
    if driver:
        try:
            driver.quit()
        except Exception:
            pass
    
    # Clear user data
    if user_id in user_data:
        user_data[user_id]['last_authenticated'] = None
    
    # Clean up profile
    profile_path = f'chrome_profile_{user_id}'
    if os.path.exists(profile_path):
        try:
            shutil.rmtree(profile_path)
        except Exception as e:
            print(f"[DEBUG] Failed to clean up profile {profile_path}: {e}")
    
    return {'message': 'Session cleared'}

@app.route('/admin/clear_all_sessions', methods=['POST'])
def admin_clear_all_sessions():
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    
    # Clear all active sessions
    for user_id, driver in list(active_drivers.items()):
        try:
            driver.quit()
        except Exception:
            pass
        active_drivers.pop(user_id, None)
        if user_id in user_data:
            user_data[user_id]['last_authenticated'] = None
    
    # Clean up all profiles
    cleanup_old_profiles(max_age_hours=0)
    
    return {'message': 'All sessions cleared'}

# Add periodic cleanup task
def periodic_cleanup():
    while True:
        try:
            cleanup_old_profiles()
        except Exception as e:
            print(f"[DEBUG] Error in periodic cleanup: {e}")
        time.sleep(3600)  # Run every hour

# Start cleanup thread
threading.Thread(target=periodic_cleanup, daemon=True).start()

# Helper to get current user
def get_chrome_driver_for_user(user_id):
    # Always quit previous driver for this user if it exists
    if user_id in active_drivers:
        try:
            active_drivers[user_id].quit()
        except Exception:
            pass
        del active_drivers[user_id]
    # Now launch a new driver
    from advancedCourseSniper import get_chrome_driver
    driver = get_chrome_driver(user_id)
    active_drivers[user_id] = driver
    return driver

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy-policy')
def privacy_policy():
    print("Privacy policy route accessed!")
    return render_template('privacy_policy.html')

@app.route('/how-to-use')
def how_to_use():
    return render_template('how-to-use.html')

@app.route('/leaderboard')
def leaderboard():
    # Aggregate course index popularity
    course_counter = {}
    for info in user_data.values():
        for course in info.get('course_indexes', []):
            course_counter[course] = course_counter.get(course, 0) + 1
        for req in info.get('past_requests', []):
            course_counter[req['index']] = course_counter.get(req['index'], 0)
    leaderboard = [
        {'index': k, 'count': v} for k, v in sorted(course_counter.items(), key=lambda x: x[1], reverse=True)
    ]
    return render_template('leaderboard.html', leaderboard=leaderboard)

@app.route('/admin/check_session/<int:user_id>')
def admin_check_session(user_id):
    if not session.get('is_admin'):
        return {'error': 'Not authorized'}, 403
    
    # Check if user has an active driver
    driver = active_drivers.get(user_id)
    is_active = False
    
    if driver:
        try:
            # Try to get the title to verify the session is still valid
            _ = driver.title
            is_active = True
        except Exception:
            # If we get an exception, the session is no longer valid
            active_drivers.pop(user_id, None)
            is_active = False
    
    return jsonify({
        'user_id': user_id,
        'active': is_active,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/waitlist')
def waitlist():
    return render_template('waitlist.html')

@app.route('/join_waitlist', methods=['POST'])
def join_waitlist():
    try:
        first_name = request.form['firstName']
        last_name = request.form['lastName']
        email = request.form['email']
        netid = request.form['netid']
        phone = request.form['phone']
        reason = request.form['reason']
        print(f"[DEBUG] Received waitlist request: {first_name} {last_name}, {email}, {netid}")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Check if email or netid already exists
        c.execute('SELECT * FROM waitlist WHERE email = ? OR netid = ?', (email, netid))
        duplicate = c.fetchone()
        print(f"[DEBUG] Duplicate check result: {duplicate}")
        if duplicate:
            conn.close()
            return jsonify({'error': 'You have already applied to the waitlist'}), 400
        # Add to waitlist
        c.execute('''
            INSERT INTO waitlist (first_name, last_name, email, netid, phone, reason)
            VALUES (?, ?, ?, ?, ?, ?)''', (first_name, last_name, email, netid, phone, reason))
        conn.commit()
        print(f"[DEBUG] Added to waitlist: {first_name} {last_name}, {email}, {netid}")
        conn.close()
        
        # Send confirmation email to user
        subject = "Welcome to the ScarletSniper Waitlist!"
        body = f"""Dear {first_name},\n\nThank you for your interest in ScarletSniper! We've received your waitlist application and will review it shortly.\n\nYour application details:\n- Name: {first_name} {last_name}\n- NetID: {netid}\n- Email: {email}\n\nWe'll notify you via email once your application has been reviewed.\n\nBest regards,\nThe ScarletSniper Team"""
        send_email(subject, body, email)
        
        # Send notification email to admin (shaheersaud2004@gmail.com)
        admin_subject = "New Waitlist Application Received"
        admin_body = f"""A new waitlist application has been received:\n\n
Name: {first_name} {last_name}
Email: {email}
NetID: {netid}
Phone: {phone}
Reason: {reason}\n\n
Please review this application in the admin dashboard."""
        send_email(admin_subject, admin_body, "shaheersaud2004@gmail.com")
        
        return jsonify({'message': 'Successfully joined waitlist'}), 200
    except Exception as e:
        print(f"Error in join_waitlist: {str(e)}")
        return jsonify({'error': 'An error occurred. Please try again.'}), 500

@app.route('/admin/waitlist')
def admin_waitlist():
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM waitlist ORDER BY created_at DESC')
    applications = c.fetchall()
    conn.close()
    return render_template('admin_waitlist.html', applications=applications, user=get_current_user())

@app.route('/admin/waitlist/data')
def admin_waitlist_data():
    if not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM waitlist ORDER BY created_at DESC')
    applications = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({'applications': applications})

@app.route('/admin/waitlist/<int:app_id>/details')
def admin_waitlist_details(app_id):
    if not session.get('is_admin'):
        return jsonify({'error': 'Not authorized'}), 403
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM waitlist WHERE id = ?', (app_id,))
    app = c.fetchone()
    conn.close()
    
    if not app:
        return jsonify({'error': 'Application not found'}), 404
    
    return jsonify(dict(app))

@app.route('/admin/waitlist/<int:app_id>/update', methods=['POST'])
def admin_update_waitlist(app_id):
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        status = request.form['status']
        if status not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid status'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get application details
        c.execute('SELECT * FROM waitlist WHERE id = ?', (app_id,))
        app = c.fetchone()
        
        if not app:
            conn.close()
            return jsonify({'error': 'Application not found'}), 404
        
        # If approving, create user account with temporary password
        if status == 'approved':
            # Check if user already exists
            c.execute('SELECT id FROM users WHERE email = ? OR netid = ?', (app['email'], app['netid']))
            if c.fetchone():
                conn.close()
                return jsonify({'error': 'A user with this email or NetID already exists.'}), 400
            
            # Generate temporary password using Firstname123 format
            temp_password = f"{app['first_name']}123"
            
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, app['email']):
                conn.close()
                return jsonify({'error': 'Invalid email format'}), 400
            
            hashed_pw = generate_password_hash(temp_password, method='pbkdf2:sha256')
            
            # Create user account
            c.execute('''
                INSERT INTO users (
                    email, password, netid, is_admin, account_type, 
                    paid_class_count, phone, phone_notifications, phone_verified,
                    temp_password
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                app['email'], hashed_pw, app['netid'], 0, 'free',
                0, app['phone'], 0, 0, temp_password
            ))
            
            # Update waitlist status
            c.execute('UPDATE waitlist SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
                     (status, app_id))
            
            conn.commit()
            conn.close()
            
            # Send approval email with login info
            subject = "Your ScarletSniper Waitlist Application Approved!"
            body = f"""Dear {app['first_name']},

Great news! Your ScarletSniper waitlist application has been approved!

Your account has been created. You can now log in at: {url_for('login', _external=True)}

Login Email: {app['email']}
Temporary Password: {temp_password}

IMPORTANT: You must change your password on your first login for security reasons.

We look forward to having you as part of the ScarletSniper community!

Best regards,
The ScarletSniper Team"""
            
            try:
                send_email(subject, body, app['email'])
                print(f"[DEBUG] Successfully sent approval email to {app['email']}")
            except Exception as e:
                print(f"[ERROR] Failed to send approval email to {app['email']}: {str(e)}")
                # Continue with user creation even if email fails
                # The user can still log in with their credentials
            
            return jsonify({'message': 'User approved and account created. Email sent.'}), 200
        
        else:  # Rejected
            # Update status to rejected
            c.execute('UPDATE waitlist SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
                     (status, app_id))
            conn.commit()
            conn.close()
            
            # Send rejection email
            subject = "Your ScarletSniper Waitlist Application Update"
            body = f"""Dear {app['first_name']},

Thank you for your interest in ScarletSniper. After reviewing your application, we regret to inform you that we cannot approve your request at this time.

We appreciate your interest and encourage you to try again in the future.

Best regards,
The ScarletSniper Team"""
            
            try:
                send_email(subject, body, app['email'])
                print(f"[DEBUG] Successfully sent rejection email to {app['email']}")
            except Exception as e:
                print(f"[ERROR] Failed to send rejection email to {app['email']}: {str(e)}")
            
            return jsonify({'message': 'Application rejected and user notified.'}), 200
            
    except Exception as e:
        print(f"Error in admin_update_waitlist: {str(e)}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/waitlist-landing')
def waitlist_landing():
    return render_template('waitlist_landing.html')

if __name__ == '__main__':
    socketio.run(app, debug=True,port=8080) 