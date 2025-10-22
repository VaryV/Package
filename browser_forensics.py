# browser_forensics.py
import os, sqlite3
from datetime import datetime, timedelta

try:
    import win32crypt
except ImportError:
    win32crypt = None

# -------------------
# Helpers
# -------------------
def chrome_time_to_dt(chrome_ts):
    """Convert Chrome/Edge/Brave timestamp to ISO string"""
    try:
        dt = datetime(1601,1,1) + timedelta(microseconds=int(chrome_ts))
        return dt.isoformat()
    except:
        return str(chrome_ts)

def firefox_time_to_dt(ff_ts):
    """Convert Firefox microseconds timestamp to ISO string"""
    try:
        dt = datetime.utcfromtimestamp(ff_ts / 1000000)
        return dt.isoformat()
    except:
        return str(ff_ts)

def decrypt_windows_chrome_pwd(encrypted_pwd):
    if not win32crypt:
        return "<win32crypt not installed>"
    try:
        return win32crypt.CryptUnprotectData(encrypted_pwd, None, None, None, 0)[1].decode()
    except:
        return "<decryption failed>"

# -------------------
# Browser profile paths
# -------------------
BROWSER_PROFILES = {
    "chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default"),
    "edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default"),
    "brave": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default"),
    "firefox": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
}

BROWSER_LOGIN_DB = {
    "chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
    "edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data"),
    "brave": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data")
}

# -------------------
# Extract browser history / downloads
# -------------------
def extract_chrome_history(profile_path):
    history_db = os.path.join(profile_path, "History")
    result = {"history": [], "downloads": []}
    if not os.path.exists(history_db):
        return result

    conn = sqlite3.connect(history_db)
    cursor = conn.cursor()

    # Browsing history
    try:
        cursor.execute("SELECT url, title, visit_count, last_visit_time, hidden FROM urls")
        for r in cursor.fetchall():
            result["history"].append({
                "url": r[0],
                "title": r[1],
                "visits": r[2],
                "last_visit": chrome_time_to_dt(r[3]),
                "deleted": bool(r[4])
            })
    except:
        pass

    # Downloads
    try:
        cursor.execute("SELECT current_path, target_path, start_time, end_time, received_bytes FROM downloads")
        for r in cursor.fetchall():
            result["downloads"].append({
                "current_path": r[0],
                "target_path": r[1],
                "start_time": chrome_time_to_dt(r[2]),
                "end_time": chrome_time_to_dt(r[3]),
                "received_bytes": r[4]
            })
    except:
        pass

    conn.close()
    return result

def extract_firefox_history(profile_dir):
    import glob
    result = {"history": [], "downloads": []}
    profiles = glob.glob(os.path.join(profile_dir, "*.default*"))
    for p in profiles:
        db = os.path.join(p, "places.sqlite")
        if not os.path.exists(db):
            continue
        try:
            conn = sqlite3.connect(db)
            cursor = conn.cursor()
            # History
            cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places")
            for r in cursor.fetchall():
                last_visit = firefox_time_to_dt(r[3]) if r[3] else None
                result["history"].append({
                    "url": r[0],
                    "title": r[1],
                    "visits": r[2],
                    "last_visit": last_visit
                })
            # Downloads
            cursor.execute("SELECT name, source, target, startDate, endDate FROM moz_annos")
            for r in cursor.fetchall():
                result["downloads"].append({
                    "name": r[0],
                    "source": r[1],
                    "target": r[2],
                    "start_time": firefox_time_to_dt(r[3]) if r[3] else None,
                    "end_time": firefox_time_to_dt(r[4]) if r[4] else None
                })
            conn.close()
        except:
            continue
    return result

# -------------------
# Extract stored passwords / autofill
# -------------------
def extract_browser_passwords():
    all_pwds = {}
    for browser, db_path in BROWSER_LOGIN_DB.items():
        if not os.path.exists(db_path):
            all_pwds[browser] = []
            continue
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        pwds = []
        try:
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                pwds.append({
                    "url": r[0],
                    "username": r[1],
                    "password": decrypt_windows_chrome_pwd(r[2])
                })
        except:
            pass
        conn.close()
        all_pwds[browser] = pwds
    return all_pwds

# -------------------
# Aggregate all browsers
# -------------------
def extract_all_browser_artifacts():
    all_results = {}
    for browser, path in BROWSER_PROFILES.items():
        if browser == "firefox":
            res = extract_firefox_history(path)
        else:
            res = extract_chrome_history(path)
        all_results[browser] = res

    # Add passwords
    all_results["passwords"] = extract_browser_passwords()
    return all_results

# -------------------
# Example usage
# -------------------
if __name__ == "__main__":
    import json
    data = extract_all_browser_artifacts()
    print(json.dumps(data, indent=2))
