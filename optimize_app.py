import os
import gc
import psutil
import threading
from datetime import datetime, timedelta

def cleanup_old_sessions():
    """Clean up old sessions and temporary files"""
    try:
        # Clean up old Chrome profiles
        for item in os.listdir('.'):
            if item.startswith('chrome_profile_'):
                profile_path = os.path.join('.', item)
                if os.path.isdir(profile_path):
                    # Check if profile is older than 24 hours
                    if datetime.fromtimestamp(os.path.getctime(profile_path)) < datetime.now() - timedelta(hours=24):
                        try:
                            import shutil
                            shutil.rmtree(profile_path)
                            print(f"Cleaned up old Chrome profile: {profile_path}")
                        except Exception as e:
                            print(f"Error cleaning up Chrome profile {profile_path}: {e}")

        # Clean up old cookie files
        for item in os.listdir('.'):
            if item.startswith('webreg_cookies_') or item.startswith('rutgers_cookies_'):
                cookie_path = os.path.join('.', item)
                if os.path.isfile(cookie_path):
                    if datetime.fromtimestamp(os.path.getctime(cookie_path)) < datetime.now() - timedelta(hours=24):
                        try:
                            os.remove(cookie_path)
                            print(f"Cleaned up old cookie file: {cookie_path}")
                        except Exception as e:
                            print(f"Error cleaning up cookie file {cookie_path}: {e}")

    except Exception as e:
        print(f"Error in cleanup_old_sessions: {e}")

def monitor_memory_usage():
    """Monitor memory usage and trigger cleanup if needed"""
    process = psutil.Process()
    memory_info = process.memory_info()
    memory_percent = process.memory_percent()
    
    print(f"Memory usage: {memory_info.rss / 1024 / 1024:.2f} MB ({memory_percent:.1f}%)")
    
    if memory_percent > 80:
        print("High memory usage detected, triggering cleanup...")
        gc.collect()
        cleanup_old_sessions()

def start_performance_monitoring():
    """Start the performance monitoring thread"""
    def monitor_loop():
        while True:
            try:
                monitor_memory_usage()
                cleanup_old_sessions()
            except Exception as e:
                print(f"Error in performance monitoring: {e}")
            finally:
                # Sleep for 5 minutes
                import time
                time.sleep(300)

    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    return monitor_thread

# Add this to your app.py
"""
from optimize_app import start_performance_monitoring

# Start performance monitoring when the app starts
monitor_thread = start_performance_monitoring()
""" 