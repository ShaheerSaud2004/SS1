import os
import time
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import re
from selenium.webdriver.common.keys import Keys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup
import shutil
from dotenv import load_dotenv

load_dotenv('secret.env')  # Explicitly load from secret.env

load_dotenv()

COOKIES_FILE = "rutgers_cookies.json"
CHECK_INTERVAL = 5  # seconds between checks
COURSE_SEMESTER = "92025"  # Fall 2025
CAMPUS = "NB"
LEVEL = "U"

DEFAULT_EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS')  # Used as sender
DEFAULT_EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')  # Used as sender's app password

def get_chrome_driver(user_id=None, try_load_cookies=True):
    options = Options()
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    if user_id:
        profile_dir = os.path.abspath(f'chrome_profile_{user_id}')
    else:
        profile_dir = os.path.abspath('chrome_profile')
    options.add_argument(f"--user-data-dir={profile_dir}")
    print(f"[DEBUG] Launching Chrome with profile: {profile_dir}")
    service = Service('/opt/homebrew/bin/chromedriver')
    driver = webdriver.Chrome(service=service, options=options)
    driver.execute_cdp_cmd('Network.setUserAgentOverride', {
        "userAgent": 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
    })
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    print("[DEBUG] Chrome driver launched successfully.")
    # Try to load cookies if requested and file exists
    if try_load_cookies and user_id:
        cookie_path = f"webreg_cookies_{user_id}.json"
        if os.path.exists(cookie_path):
            print(f"[DEBUG] Attempting to load cookies for user {user_id}")
            load_cookies(driver, user_id)
    return driver

def get_cookie_file(user_id=None):
    if user_id:
        return f"rutgers_cookies_{user_id}.json"
    return "rutgers_cookies.json"

def save_cookies(driver, user_id):
    cookies = driver.get_cookies()
    with open(f"webreg_cookies_{user_id}.json", "w") as f:
        json.dump(cookies, f)

def load_cookies(driver, user_id):
    import time
    try:
        with open(f"webreg_cookies_{user_id}.json", "r") as f:
            cookies = json.load(f)
        driver.get("https://sims.rutgers.edu/webreg/chooseSemester.htm?login=cas")
        for cookie in cookies:
            driver.add_cookie(cookie)
        driver.refresh()
        time.sleep(1)
        return True
    except Exception as e:
        print(f"[DEBUG] Could not load cookies: {e}")
        return False

def login_and_save_cookies(driver, course_index, netid, password, user_id=None):
    driver.get("https://sims.rutgers.edu/webreg/chooseSemester.htm?login=cas")
    WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "username")))
    time.sleep(1)
    driver.find_element(By.ID, "username").send_keys(netid)
    driver.find_element(By.ID, "password").send_keys(password)
    driver.find_element(By.NAME, "submit").click()
    try:
        yes_button = WebDriverWait(driver, 5).until(
            EC.element_to_be_clickable((By.XPATH, "//button[contains(., 'Yes, this is my device')]"))
        )
        driver.execute_script("arguments[0].click();", yes_button)
        time.sleep(2)
    except Exception:
        pass
    try:
        continue_btn = WebDriverWait(driver, 5).until(
            EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div[1]/form/div/input"))
        )
        driver.execute_script("arguments[0].click();", continue_btn)
        time.sleep(1)
        if driver.current_url.startswith("https://sims.rutgers.edu/webreg/refresh.htm"):
            target_url = f"https://sims.rutgers.edu/webreg/editSchedule.htm?login=cas&semesterSelection=92025&indexList={course_index}"
            driver.get(target_url)
            time.sleep(1)
            save_cookies(driver, user_id)  # Save cookies after login
            register_for_course(driver, course_index)
            return True
    except Exception:
        pass
    try:
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.XPATH, "//h2[contains(text(), 'Choose Semester')]") )
        )
        save_cookies(driver, user_id)  # Save cookies after login
        time.sleep(2)
        register_for_course(driver, course_index)
        return True
    except Exception:
        return False

def ensure_logged_in(driver, course_index, netid, password, user_id=None):
    cookie_file = get_cookie_file(user_id)
    if os.path.exists(cookie_file):
        load_cookies(driver, user_id)
        driver.get("https://sims.rutgers.edu/webreg/chooseSemester.htm?login=cas")
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, "//h2[contains(text(), 'Choose Semester')]") ))
            register_for_course(driver, course_index)
            return True
        except Exception:
            print("[DEBUG] Session expired or cookies invalid, re-logging in...")
    # If cookies fail, do full login and save cookies
    return login_and_save_cookies(driver, course_index, netid, password, user_id)

def register_for_course(driver, course_index):
    refresh_url = "https://sims.rutgers.edu/webreg/refresh.htm"
    target_url = f"https://sims.rutgers.edu/webreg/editSchedule.htm?login=cas&semesterSelection=92025&indexList={course_index}"
    max_wait = 10
    waited = 0
    while driver.current_url.startswith(refresh_url) and waited < max_wait:
        time.sleep(1)
        waited += 1
        driver.get(target_url)
        time.sleep(1)
        if driver.current_url == target_url:
            break
    if driver.current_url.startswith(refresh_url):
        return False
    try:
        add_courses_btn = WebDriverWait(driver, 5).until(
            EC.element_to_be_clickable((By.XPATH, "//input[@value='ADD COURSES →']"))
        )
        driver.execute_script("arguments[0].click();", add_courses_btn)
    except Exception:
        try:
            index_box = driver.find_element(By.ID, "i1")
            index_box.send_keys(Keys.ENTER)
        except Exception:
            pass
    time.sleep(2)
    page_source = driver.page_source
    soup = BeautifulSoup(page_source, 'html.parser')
    try:
        li_msg = driver.find_element(By.XPATH, "/html/body/div[2]/div[1]/ul/li").text
        confirmation_msg = f"Confirmation message on page:\n{li_msg}"
    except Exception:
        reg_courses = soup.find('div', {'class': 'registeredCourses'})
        confirmation_msg = reg_courses.get_text(separator='\n', strip=True) if reg_courses else 'Course index found in page.'
    if course_index in page_source:
        return True
    else:
        return False

def extract_number(text):
    match = re.search(r'\d+', text)
    return int(match.group()) if match else 0

def check_course_open(course_index):
    url = f"https://classes.rutgers.edu/soc/#keyword?keyword={course_index}&semester={COURSE_SEMESTER}&campus={CAMPUS}&level={LEVEL}"
    driver = get_chrome_driver()
    try:
        driver.get(url)
        wait = WebDriverWait(driver, 30)
        numerator_xpath = "/html/body/main/div[2]/table/tbody/tr/td[2]/div[5]/div[1]/div/div/div/div/div[2]/span[5]/span"
        try:
            numerator_elem = wait.until(EC.presence_of_element_located((By.XPATH, numerator_xpath)))
            numerator = extract_number(numerator_elem.text)
            return numerator > 0
        except Exception:
            return 'invalid'
    except Exception:
        return False
    finally:
        driver.quit()

def send_email(subject, body, to_addr=None, from_addr=DEFAULT_EMAIL_ADDRESS, from_pass=DEFAULT_EMAIL_PASSWORD):
    print(f"[DEBUG] Attempting to send email to {to_addr}")
    print(f"[DEBUG] Using from_addr: {from_addr}")
    
    if not from_addr or not from_pass:
        print("[ERROR] Email configuration missing. Please set EMAIL_ADDRESS and EMAIL_PASSWORD in your environment.")
        print(f"[DEBUG] from_addr: {from_addr}")
        print(f"[DEBUG] from_pass: {'*' * len(from_pass) if from_pass else None}")
        return False
        
    if not to_addr:
        print("[ERROR] No recipient email address provided.")
        return False
        
    try:
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        print("[DEBUG] Connecting to SMTP server...")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        print("[DEBUG] Logging in to SMTP server...")
        server.login(from_addr, from_pass)
        text = msg.as_string()
        print("[DEBUG] Sending email...")
        server.sendmail(from_addr, to_addr, text)
        server.quit()
        print(f"[DEBUG] Email sent successfully to {to_addr}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send email: {str(e)}")
        print(f"[DEBUG] Full error details: {type(e).__name__}: {str(e)}")
        return False 