# app.py
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Boolean, inspect
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, configure_mappers
import datetime
import os
import json
import hashlib
import tempfile
import shutil
from groq import Groq
from dotenv import load_dotenv
import pytsk3
import subprocess
import winreg
import codecs
import sqlite3
import glob
from datetime import timedelta
try:
    import win32crypt
except ImportError:
    win32crypt = None
import re
import base64
import io
import mimetypes
import zipfile
from collections import defaultdict, Counter
try:
    from scapy.all import rdpcap, TCP, Raw, IP, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
import mimetypes
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    
# Load environment variables from .env file
load_dotenv()

# Initialize Groq client
client = Groq()

# Define DB models
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    is_admin = Column(Boolean, default=False)
    
    # Relationships
    assigned_cases = relationship('Case', back_populates='enquiring_officer')
    team_memberships = relationship('TeamMember', back_populates='member')
    access_logs = relationship('AccessLog', back_populates='user')

class Case(Base):
    __tablename__ = 'cases'
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    enquiring_officer_id = Column(Integer, ForeignKey('users.id'))
    enquiring_officer = relationship('User', back_populates='assigned_cases')
    evidences = relationship('Evidence', back_populates='case', cascade='all, delete-orphan')
    team_members = relationship('TeamMember', back_populates='case', cascade='all, delete-orphan')
    access_logs = relationship('AccessLog', back_populates='case')

class TeamMember(Base):
    __tablename__ = 'team_members'
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Relationships
    case = relationship('Case', back_populates='team_members')
    member = relationship('User', back_populates='team_memberships')

class Evidence(Base):
    __tablename__ = 'evidences'
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    file_name = Column(String(100), nullable=False)
    file_path = Column(String(255), nullable=False)
    evidence_metadata = Column(Text)  # JSON string for additional metadata
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    case = relationship('Case', back_populates='evidences')
    access_logs = relationship('AccessLog', back_populates='evidence')

class AccessLog(Base):
    __tablename__ = 'access_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    evidence_id = Column(Integer, ForeignKey('evidences.id'), nullable=True)  # Null if case-level access
    operation = Column(String(50), nullable=False)  # e.g., 'view_case', 'analyze_evidence'
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # NEW FIELDS for Chain of Custody
    query = Column(Text, nullable=True)  # User's natural language query
    tool_called = Column(String(100), nullable=True)  # Name of the tool that was called
    tool_arguments = Column(Text, nullable=True)  # JSON string of tool arguments
    tool_result = Column(Text, nullable=True)  # Result returned by the tool
    llm_response = Column(Text, nullable=True)  # Final LLM response to user
    
    # Relationships
    user = relationship('User', back_populates='access_logs')
    case = relationship('Case', back_populates='access_logs')
    evidence = relationship('Evidence', back_populates='access_logs')

# Force configuration of mappers after all classes defined
configure_mappers()

# Setup DB with check to avoid recreation
engine = create_engine('sqlite:///forensics.db')
inspector = inspect(engine)

# Create all tables if database is new
if not inspector.has_table('users'):
    Base.metadata.create_all(engine)
    print("✓ Database created with all tables")
else:
    # For existing database, try to add new columns if they don't exist
    try:
        # This will add any missing columns/tables
        Base.metadata.create_all(engine)
        
        # Verify and add missing columns to access_logs if needed
        with engine.connect() as conn:
            # Check if new columns exist in access_logs
            result = conn.execute("PRAGMA table_info(access_logs)").fetchall()
            existing_columns = [row[1] for row in result]
            
            new_columns = {
                'query': 'TEXT',
                'tool_called': 'VARCHAR(100)',
                'tool_arguments': 'TEXT',
                'tool_result': 'TEXT',
                'llm_response': 'TEXT'
            }
            
            for col_name, col_type in new_columns.items():
                if col_name not in existing_columns:
                    conn.execute(f"ALTER TABLE access_logs ADD COLUMN {col_name} {col_type}")
                    conn.commit()
                    print(f"✓ Added column '{col_name}' to access_logs table")
    except Exception as e:
        print(f"Note: Schema update attempt: {e}")

Session = sessionmaker(bind=engine)

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    return stored_hash == hashlib.sha256(password.encode()).hexdigest()

def log_access(session, user_id, case_id, evidence_id=None, operation='view', 
               query=None, tool_called=None, tool_arguments=None, tool_result=None, llm_response=None):
    """Enhanced logging function with chain of custody details"""
    log = AccessLog(
        user_id=user_id, 
        case_id=case_id, 
        evidence_id=evidence_id, 
        operation=operation,
        query=query,
        tool_called=tool_called,
        tool_arguments=tool_arguments,
        tool_result=tool_result,
        llm_response=llm_response
    )
    session.add(log)
    session.commit()
    return log

def init_data(session):
    """Initialize default users if they don't exist"""
    # Create admin user
    admin = session.query(User).filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password_hash=hash_password('adminpass'), is_admin=True)
        session.add(admin)
        print("✓ Created admin user (username: admin, password: adminpass)")
    
    # Create officer1 user
    user1 = session.query(User).filter_by(username='officer1').first()
    if not user1:
        user1 = User(username='officer1', password_hash=hash_password('pass1'), is_admin=False)
        session.add(user1)
        print("✓ Created officer1 user (username: officer1, password: pass1)")
    
    # Create member1 user
    user2 = session.query(User).filter_by(username='member1').first()
    if not user2:
        user2 = User(username='member1', password_hash=hash_password('pass2'), is_admin=False)
        session.add(user2)
        print("✓ Created member1 user (username: member1, password: pass2)")
    
    session.commit()
    
    # Display summary
    total_users = session.query(User).count()
    print(f"✓ Database initialized with {total_users} users")

# Existing backend functions
def file_signature_analysis(file_content: bytes, ext: str) -> str:
    header = file_content[:12]
    ext = ext.lower()
    signatures = {
        '.jpg': b'\xff\xd8\xff',
        '.png': b'\x89PNG\r\n\x1a\n',
        '.pdf': b'%PDF-',
        '.docx': b'PK\x03\x04',
    }
    expected_sig = signatures.get(ext)
    if expected_sig and header.startswith(expected_sig):
        return f"Match: The file extension '{ext}' matches the content signature."
    else:
        return f"Mismatch: The file extension '{ext}' does not match the content signature. Actual header: {header.hex()}"

def carve_jpegs_from_doc(file_content: bytes) -> str:
    data = file_content
    temp_dir = tempfile.mkdtemp()
    carved_files = []
    start_marker = b'\xff\xd8\xff'
    end_marker = b'\xff\xd9'
    pos = 0
    while True:
        start_pos = data.find(start_marker, pos)
        if start_pos == -1:
            break
        end_pos = data.find(end_marker, start_pos)
        if end_pos == -1:
            break
        jpeg_data = data[start_pos:end_pos + 2]
        output_path = os.path.join(temp_dir, f"carved_jpeg_{len(carved_files)}.jpg")
        with open(output_path, 'wb') as out_f:
            out_f.write(jpeg_data)
        carved_files.append(output_path)
        pos = end_pos + 2
    if carved_files:
        return f"Carved {len(carved_files)} JPEG images to {temp_dir}:\n" + "\n".join(carved_files)
    return "No JPEG images found in the file."

def capture_disk_image(source_device: str) -> str:
    CHUNK_SIZE = 1024 * 1024
    temp_dir = tempfile.mkdtemp()
    output_file = os.path.join(temp_dir, "captured_disk.img")
    try:
        with open(source_device, "rb") as src, open(output_file, "wb") as dst:
            total_bytes = 0
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(chunk)
                total_bytes += len(chunk)
                print(f"\r[+] Captured {total_bytes / (1024*1024):.2f} MB", end="")
        print(f"\n[✓] Disk image successfully saved to {output_file}")
        return f"Captured disk image saved to {output_file} (size: {total_bytes} bytes)"
    except PermissionError:
        return "[!] Permission denied. Run this script as administrator/root."
    except FileNotFoundError:
        return f"[!] Source device {source_device} not found."
    except Exception as e:
        return f"[!] Error: {str(e)}"

def recover_deleted_files(file_content: bytes) -> str:
    temp_dir = tempfile.mkdtemp()
    image_path = os.path.join(temp_dir, "disk_image.img")
    with open(image_path, "wb") as f:
        f.write(file_content)
    output_dir = os.path.join(temp_dir, "recovered_files")
    os.makedirs(output_dir, exist_ok=True)
    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img, offset=0)
        recovered_paths = []
        def export_file(f, path):
            if not f.info.meta or f.info.meta.size == 0:
                return
            size = f.info.meta.size
            name = f.info.name.name.decode(errors="ignore")
            safe_name = f"DELETED_{f.info.meta.addr}_{name}"
            out_path = os.path.join(output_dir, safe_name)
            with open(out_path, "wb") as out:
                offset = 0
                while offset < size:
                    available = min(1024 * 1024, size - offset)
                    data = f.read_random(offset, available)
                    if not data:
                        break
                    out.write(data)
                    offset += len(data)
            recovered_paths.append(out_path)
            print(f"[+] Recovered: {out_path} (size={size})")
        def walk_directory(directory, path="/"):
            for f in directory:
                try:
                    name = f.info.name.name.decode(errors="ignore")
                except:
                    continue
                if name in [".", ".."]:
                    continue
                if f.info.meta:
                    if f.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                        if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                            export_file(f, path)
                if f.info.meta and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        subdir = f.as_directory()
                        walk_directory(subdir, os.path.join(path, name))
                    except Exception:
                        continue
        root_dir = fs.open_dir(path="/")
        walk_directory(root_dir)
        if recovered_paths:
            return f"Recovered {len(recovered_paths)} files to {output_dir}:\n" + "\n".join(recovered_paths)
        return "No deleted files recovered."
    except Exception as e:
        return f"[!] Error recovering files: {str(e)}"
    finally:
        try:
            os.unlink(image_path)
        except:
            pass

def analyze_windows_registry(action: str) -> str:
    """
    Analyze Windows Registry for forensic artifacts.
    Supports: typedurls, run, runonce, recentdocs, userassist, usb, installedapps, services
    """
    def read_registry_values(root, path, recursive=False):
        """Reads registry values with safe decoding."""
        data = {}
        try:
            access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(root, path, 0, access) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if isinstance(value, bytes):
                            try:
                                value = value.decode("utf-16", errors="ignore").strip("\x00")
                            except Exception:
                                value = value.decode("utf-8", errors="ignore")
                        data[name] = value
                        i += 1
                    except OSError:
                        break
                
                if recursive:
                    j = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, j)
                            sub_path = f"{path}\\{subkey_name}"
                            data[subkey_name] = read_registry_values(root, sub_path, recursive=False)
                            j += 1
                        except OSError:
                            break
        except PermissionError:
            data = {"error": f"Permission denied: {path}. Run as Administrator."}
        except FileNotFoundError:
            data = {"error": f"Registry path not found: {path}"}
        except Exception as e:
            data = {"error": str(e)}
        return data
    
    # Registry analyzers
    action = action.lower().strip()
    
    try:
        if action == "typedurls":
            result = read_registry_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\TypedURLs")
            return f"Typed URLs found: {json.dumps(result, indent=2)}"
        
        elif action == "run":
            result = read_registry_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            return f"Startup programs: {json.dumps(result, indent=2)}"
        
        elif action == "runonce":
            result = read_registry_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
            return f"RunOnce programs: {json.dumps(result, indent=2)}"
        
        elif action == "recentdocs":
            result = read_registry_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
            return f"Recent documents: {json.dumps(result, indent=2)}"
        
        elif action == "userassist":
            path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            decoded = {}
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as main_key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(main_key, i)
                        decoded_name = codecs.decode(subkey_name, "rot_13")
                        decoded[decoded_name] = "Subkey found"
                        i += 1
                    except OSError:
                        break
            return f"UserAssist entries: {json.dumps(decoded, indent=2)}"
        
        elif action == "usb":
            result = read_registry_values(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB", recursive=True)
            return f"USB device history: {json.dumps(result, indent=2)}"
        
        elif action == "installedapps":
            apps64 = read_registry_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", recursive=True)
            apps32 = read_registry_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", recursive=True)
            return f"Installed applications:\n64-bit: {json.dumps(apps64, indent=2)}\n32-bit: {json.dumps(apps32, indent=2)}"
        
        elif action == "services":
            result = read_registry_values(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", recursive=True)
            return f"Windows services: {json.dumps(result, indent=2)}"
        
        else:
            return f"Unknown registry action '{action}'. Supported: typedurls, run, runonce, recentdocs, userassist, usb, installedapps, services"
    
    except Exception as e:
        return f"Registry analysis error: {str(e)}"

def analyze_browser_forensics(browser: str, artifact_type: str) -> str:
    """
    Extract browser forensic artifacts.
    Supports browsers: chrome, edge, brave, firefox
    Artifact types: history, downloads, passwords, all
    """
    def chrome_time_to_dt(chrome_ts):
        try:
            dt = datetime.datetime(1601,1,1) + timedelta(microseconds=int(chrome_ts))
            return dt.isoformat()
        except:
            return str(chrome_ts)
    
    def firefox_time_to_dt(ff_ts):
        try:
            dt = datetime.datetime.utcfromtimestamp(ff_ts / 1000000)
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
    
    def extract_chrome_history(profile_path):
        history_db = os.path.join(profile_path, "History")
        result = {"history": [], "downloads": []}
        if not os.path.exists(history_db):
            return result
        
        try:
            conn = sqlite3.connect(history_db)
            cursor = conn.cursor()
            
            # Browsing history
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls LIMIT 100")
            for r in cursor.fetchall():
                result["history"].append({
                    "url": r[0],
                    "title": r[1],
                    "visits": r[2],
                    "last_visit": chrome_time_to_dt(r[3])
                })
            
            # Downloads
            cursor.execute("SELECT current_path, target_path, start_time, end_time, received_bytes FROM downloads LIMIT 50")
            for r in cursor.fetchall():
                result["downloads"].append({
                    "current_path": r[0],
                    "target_path": r[1],
                    "start_time": chrome_time_to_dt(r[2]),
                    "end_time": chrome_time_to_dt(r[3]),
                    "received_bytes": r[4]
                })
            
            conn.close()
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def extract_firefox_history(profile_dir):
        result = {"history": [], "downloads": []}
        profiles = glob.glob(os.path.join(profile_dir, "*.default*"))
        for p in profiles:
            db = os.path.join(p, "places.sqlite")
            if not os.path.exists(db):
                continue
            try:
                conn = sqlite3.connect(db)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places LIMIT 100")
                for r in cursor.fetchall():
                    last_visit = firefox_time_to_dt(r[3]) if r[3] else None
                    result["history"].append({
                        "url": r[0],
                        "title": r[1],
                        "visits": r[2],
                        "last_visit": last_visit
                    })
                conn.close()
            except Exception as e:
                result["error"] = str(e)
        return result
    
    def extract_browser_passwords(browser_name):
        if browser_name not in BROWSER_LOGIN_DB:
            return []
        
        db_path = BROWSER_LOGIN_DB[browser_name]
        if not os.path.exists(db_path):
            return []
        
        pwds = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins LIMIT 50")
            for r in cursor.fetchall():
                pwds.append({
                    "url": r[0],
                    "username": r[1],
                    "password": decrypt_windows_chrome_pwd(r[2])
                })
            conn.close()
        except Exception as e:
            pwds = [{"error": str(e)}]
        
        return pwds
    
    # Main logic
    browser = browser.lower().strip()
    artifact_type = artifact_type.lower().strip()
    
    try:
        if browser not in BROWSER_PROFILES:
            return f"Unknown browser '{browser}'. Supported: chrome, edge, brave, firefox"
        
        profile_path = BROWSER_PROFILES[browser]
        
        if artifact_type == "history":
            if browser == "firefox":
                data = extract_firefox_history(profile_path)
                return f"Firefox browsing history:\n{json.dumps(data['history'], indent=2)}"
            else:
                data = extract_chrome_history(profile_path)
                return f"{browser.capitalize()} browsing history:\n{json.dumps(data['history'], indent=2)}"
        
        elif artifact_type == "downloads":
            if browser == "firefox":
                data = extract_firefox_history(profile_path)
                return f"Firefox downloads:\n{json.dumps(data['downloads'], indent=2)}"
            else:
                data = extract_chrome_history(profile_path)
                return f"{browser.capitalize()} downloads:\n{json.dumps(data['downloads'], indent=2)}"
        
        elif artifact_type == "passwords":
            if browser == "firefox":
                return "Firefox password extraction requires additional tools (not implemented)"
            else:
                pwds = extract_browser_passwords(browser)
                return f"{browser.capitalize()} stored passwords:\n{json.dumps(pwds, indent=2)}"
        
        elif artifact_type == "all":
            if browser == "firefox":
                data = extract_firefox_history(profile_path)
            else:
                data = extract_chrome_history(profile_path)
                if browser in BROWSER_LOGIN_DB:
                    data["passwords"] = extract_browser_passwords(browser)
            return f"{browser.capitalize()} all artifacts:\n{json.dumps(data, indent=2)}"
        
        else:
            return f"Unknown artifact type '{artifact_type}'. Supported: history, downloads, passwords, all"
    
    except Exception as e:
        return f"Browser forensics error: {str(e)}"
def analyze_network_pcap(file_content: bytes, analysis_type: str) -> str:
    """
    Analyze PCAP/PCAPNG files for network forensics.
    Analysis types: summary, credentials, files, http_traffic, suspicious_ips
    """
    if not SCAPY_AVAILABLE:
        return "Error: scapy library not installed. Install with: pip install scapy"
    
    def iso(ts):
        try:
            return datetime.datetime.utcfromtimestamp(float(ts)).isoformat() + "Z"
        except:
            return str(ts)
    
    def is_private_ip(ip):
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            return False
        except:
            return False
    
    def build_tcp_streams(packets):
        streams = defaultdict(list)
        for pkt in packets:
            try:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif IPv6 in pkt:
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                else:
                    continue
                if TCP in pkt:
                    payload = bytes(pkt[TCP].payload) if Raw in pkt or len(bytes(pkt[TCP].payload))>0 else b""
                    if payload:
                        key = (src, dst, pkt[TCP].sport, pkt[TCP].dport)
                        streams[key].append((pkt.time, payload))
            except Exception:
                continue
        return streams
    
    _http_request_re = re.compile(br'^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/1\.[01]', re.I | re.M)
    _http_response_re = re.compile(br'^HTTP/1\.[01]\s+(\d{3})\s+([^\r\n]+)', re.I | re.M)
    _header_split_re = re.compile(br'\r\n\r\n', re.M)
    _header_line_re = re.compile(br'(?P<name>[^:\r\n]+):\s*(?P<value>[^\r\n]+)', re.I)
    
    def parse_http_messages(stream_bytes):
        messages = []
        i = 0
        data = stream_bytes
        L = len(data)
        while i < L and len(messages) < 50:  # Limit to 50 messages
            m_req = _http_request_re.search(data[i:i+4096])
            m_resp = _http_response_re.search(data[i:i+4096])
            matches = []
            if m_req:
                matches.append(('req', m_req.start()+i, m_req))
            if m_resp:
                matches.append(('resp', m_resp.start()+i, m_resp))
            if not matches:
                break
            matches.sort(key=lambda x: x[1])
            kind, start_pos, m = matches[0]
            hs = _header_split_re.search(data[start_pos:])
            if not hs:
                break
            header_end = start_pos + hs.start()
            header_blob = data[start_pos:header_end]
            headers = {}
            for hl in _header_line_re.finditer(header_blob):
                try:
                    name = hl.group('name').decode(errors='ignore').strip()
                    value = hl.group('value').decode(errors='ignore').strip()
                    headers[name.lower()] = value
                except:
                    continue
            body_start = header_end + 4
            content_length = None
            if 'content-length' in headers:
                try:
                    content_length = int(headers['content-length'])
                except:
                    content_length = None
            if headers.get('transfer-encoding','').lower() == 'chunked' or content_length is None:
                next_header = _http_request_re.search(data[body_start:]) or _http_response_re.search(data[body_start:])
                body_end = body_start + next_header.start() if next_header else min(body_start + 10000, L)
            else:
                body_end = min(body_start + content_length, L)
            body = data[body_start:body_end]
            message = {"type": "request" if kind=='req' else "response",
                       "start": start_pos, "end": body_end,
                       "headers": headers, "body": body[:1000]}  # Limit body size
            messages.append(message)
            i = body_end
        return messages
    
    def detect_credentials_in_http(headers, body):
        creds = []
        auth = headers.get('authorization')
        if auth and auth.lower().startswith('basic '):
            try:
                b64 = auth.split(None,1)[1]
                decoded = base64.b64decode(b64).decode(errors='ignore')
                if ':' in decoded:
                    user, pwd = decoded.split(':',1)
                    creds.append({'type':'http_basic', 'user':user, 'pass':pwd})
            except:
                pass
        try:
            txt = body.decode(errors='ignore')
            for keypair in (('username','password'), ('user','pass'), ('login','password')):
                ukey, pkey = keypair
                if ukey in txt and pkey in txt:
                    m = re.search(r'([&\?]|^)' + re.escape(ukey) + r'=([^&\s]+).*?' + re.escape(pkey) + r'=([^&\s]+)', txt, re.I | re.S)
                    if m:
                        creds.append({'type':'http_form', 'user':m.group(2), 'pass':m.group(3)})
                        break
            if 'password=' in txt.lower():
                m = re.search(r'password=([^&\s]+)', txt, re.I)
                if m:
                    creds.append({'type':'http_password_field', 'password': m.group(1)})
        except:
            pass
        return creds
    
    # Save PCAP to temp file and read it
    temp_dir = tempfile.mkdtemp()
    pcap_path = os.path.join(temp_dir, "capture.pcap")
    
    try:
        with open(pcap_path, "wb") as f:
            f.write(file_content)
        
        packets = rdpcap(pcap_path)
        
        if not packets:
            return "No packets found in PCAP file"
        
        analysis_type = analysis_type.lower().strip()
        
        if analysis_type == "summary":
            # Generate summary
            ip_counter = Counter()
            for pkt in packets:
                try:
                    if IP in pkt:
                        ip_counter[pkt[IP].src] += 1
                except:
                    continue
            
            summary = {
                "total_packets": len(packets),
                "start_time": iso(packets[0].time),
                "end_time": iso(packets[-1].time),
                "unique_ips": len(ip_counter),
                "top_talkers": [{"ip": ip, "packets": count} for ip, count in ip_counter.most_common(10)]
            }
            return f"PCAP Summary:\n{json.dumps(summary, indent=2)}"
        
        elif analysis_type == "credentials":
            # Extract credentials
            streams = build_tcp_streams(packets)
            credentials = []
            
            for (src, dst, sport, dport), entries in streams.items():
                entries.sort(key=lambda x: x[0])
                blob = b"".join(p for _, p in entries)
                http_msgs = parse_http_messages(blob)
                
                for msg in http_msgs:
                    creds = detect_credentials_in_http(msg.get("headers", {}), msg.get("body", b""))
                    for c in creds:
                        credentials.append({
                            "protocol": "HTTP",
                            "src": src,
                            "dst": dst,
                            "credential": c,
                            "time": iso(entries[0][0])
                        })
            
            if credentials:
                return f"Found {len(credentials)} credentials:\n{json.dumps(credentials, indent=2)}"
            else:
                return "No credentials found in PCAP"
        
        elif analysis_type == "http_traffic":
            # Extract HTTP traffic
            streams = build_tcp_streams(packets)
            http_requests = []
            
            for (src, dst, sport, dport), entries in streams.items():
                entries.sort(key=lambda x: x[0])
                blob = b"".join(p for _, p in entries)
                http_msgs = parse_http_messages(blob)
                
                for msg in http_msgs:
                    if msg["type"] == "request":
                        # Parse request line
                        req_line = blob[msg["start"]:msg["start"]+200].split(b'\r\n')[0].decode(errors='ignore')
                        http_requests.append({
                            "src": src,
                            "dst": dst,
                            "request": req_line,
                            "host": msg["headers"].get("host", "unknown"),
                            "time": iso(entries[0][0])
                        })
            
            if http_requests:
                return f"Found {len(http_requests)} HTTP requests:\n{json.dumps(http_requests[:50], indent=2)}"
            else:
                return "No HTTP traffic found in PCAP"
        
        elif analysis_type == "files":
            # Detect file transfers (simplified)
            streams = build_tcp_streams(packets)
            file_transfers = []
            
            for (src, dst, sport, dport), entries in streams.items():
                entries.sort(key=lambda x: x[0])
                blob = b"".join(p for _, p in entries)
                http_msgs = parse_http_messages(blob)
                
                for msg in http_msgs:
                    if msg["type"] == "response":
                        ctype = msg["headers"].get("content-type", "")
                        if any(t in ctype for t in ["image", "application", "video", "audio"]):
                            file_transfers.append({
                                "src": src,
                                "dst": dst,
                                "content_type": ctype,
                                "size": len(msg["body"]),
                                "time": iso(entries[0][0])
                            })
            
            if file_transfers:
                return f"Found {len(file_transfers)} file transfers:\n{json.dumps(file_transfers[:30], indent=2)}"
            else:
                return "No file transfers detected in PCAP"
        
        elif analysis_type == "suspicious_ips":
            # Detect suspicious IPs (non-private IPs with credentials)
            streams = build_tcp_streams(packets)
            suspicious = set()
            
            for (src, dst, sport, dport), entries in streams.items():
                entries.sort(key=lambda x: x[0])
                blob = b"".join(p for _, p in entries)
                http_msgs = parse_http_messages(blob)
                
                for msg in http_msgs:
                    creds = detect_credentials_in_http(msg.get("headers", {}), msg.get("body", b""))
                    if creds:
                        if not is_private_ip(src):
                            suspicious.add(src)
                        if not is_private_ip(dst):
                            suspicious.add(dst)
            
            if suspicious:
                return f"Found {len(suspicious)} suspicious IPs:\n{json.dumps(list(suspicious), indent=2)}"
            else:
                return "No suspicious IPs detected"
        
        else:
            return f"Unknown analysis type '{analysis_type}'. Supported: summary, credentials, files, http_traffic, suspicious_ips"
    
    except Exception as e:
        return f"PCAP analysis error: {str(e)}"
    
    finally:
        try:
            os.unlink(pcap_path)
            os.rmdir(temp_dir)
        except:
            pass
def extract_file_metadata(file_content: bytes, filename: str, metadata_type: str) -> str:
    """
    Extract metadata from files including hashes, timestamps, EXIF data.
    Metadata types: basic, hashes, exif, all
    """
    def get_file_hash_from_content(data: bytes):
        """Generate MD5, SHA1, SHA256 hashes from file content."""
        hashes = {}
        try:
            hashes["MD5"] = hashlib.md5(data).hexdigest()
            hashes["SHA1"] = hashlib.sha1(data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            hashes["Error"] = str(e)
        return hashes
    
    def extract_exif_data_from_content(file_content: bytes):
        """Extract EXIF metadata from image content."""
        if not PIL_AVAILABLE:
            return {"error": "PIL/Pillow library not installed"}
        
        exif_data = {}
        try:
            import io
            img = Image.open(io.BytesIO(file_content))
            info = img._getexif()
            if info:
                for tag, val in info.items():
                    tag_name = TAGS.get(tag, tag)
                    # Convert bytes to string for JSON serialization
                    if isinstance(val, bytes):
                        try:
                            val = val.decode('utf-8', errors='ignore')
                        except:
                            val = str(val)
                    exif_data[tag_name] = str(val) if not isinstance(val, (str, int, float)) else val
        except Exception as e:
            exif_data["error"] = str(e)
        return exif_data
    
    metadata_type = metadata_type.lower().strip()
    
    try:
        # Basic metadata
        basic_metadata = {
            "File Name": filename,
            "File Size (bytes)": len(file_content),
            "File Size (KB)": round(len(file_content) / 1024, 2),
            "File Size (MB)": round(len(file_content) / (1024 * 1024), 2),
            "File Type": mimetypes.guess_type(filename)[0] or "Unknown",
            "Extension": os.path.splitext(filename)[1] or "None"
        }
        
        if metadata_type == "basic":
            return f"Basic Metadata:\n{json.dumps(basic_metadata, indent=2)}"
        
        elif metadata_type == "hashes":
            hashes = get_file_hash_from_content(file_content)
            return f"File Hashes:\n{json.dumps(hashes, indent=2)}"
        
        elif metadata_type == "exif":
            # Check if file is an image
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ['.jpg', '.jpeg', '.png', '.tiff', '.gif', '.bmp']:
                return "EXIF data only available for image files (JPEG, PNG, TIFF, etc.)"
            
            exif_data = extract_exif_data_from_content(file_content)
            if not exif_data or "error" in exif_data:
                return f"No EXIF data found or error: {exif_data.get('error', 'Unknown error')}"
            
            return f"EXIF Metadata:\n{json.dumps(exif_data, indent=2)}"
        
        elif metadata_type == "all":
            # Combine all metadata
            all_metadata = basic_metadata.copy()
            
            # Add hashes
            hashes = get_file_hash_from_content(file_content)
            all_metadata["Hashes"] = hashes
            
            # Add EXIF if image
            ext = os.path.splitext(filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.tiff', '.gif', '.bmp']:
                exif_data = extract_exif_data_from_content(file_content)
                if exif_data and "error" not in exif_data:
                    all_metadata["EXIF Data"] = exif_data
            
            # Add file signature info
            header = file_content[:16].hex()
            all_metadata["File Header (hex)"] = header
            
            return f"Complete Metadata:\n{json.dumps(all_metadata, indent=2)}"
        
        else:
            return f"Unknown metadata type '{metadata_type}'. Supported: basic, hashes, exif, all"
    
    except Exception as e:
        return f"Metadata extraction error: {str(e)}"
    
# Tool definitions for LLM
tools = [
    {
        "type": "function",
        "function": {
            "name": "file_signature_analysis",
            "description": "Analyze the file signature to check if the extension matches the actual content type.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "carve_jpegs_from_doc",
            "description": "Carve out embedded JPEG images from a Word document or similar binary file.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "capture_disk_image",
            "description": "Capture a raw disk image from a device (e.g., /dev/sda). Provide the source device path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_device": {
                        "type": "string",
                        "description": "The path to the source device (e.g., /dev/sda or \\\\.\\PhysicalDrive0)."
                    }
                },
                "required": ["source_device"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "recover_deleted_files",
            "description": "Recover deleted files from a disk/partition image using the uploaded file as the image.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_windows_registry",
            "description": "Analyze Windows Registry for forensic artifacts like browser history (TypedURLs), startup programs (Run keys), recent documents, UserAssist, USB history, installed applications, and services. Specify the registry action type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Registry action to perform. Options: typedurls, run, runonce, recentdocs, userassist, usb, installedapps, services",
                        "enum": ["typedurls", "run", "runonce", "recentdocs", "userassist", "usb", "installedapps", "services"]
                    }
                },
                "required": ["action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_browser_forensics",
            "description": "Extract forensic artifacts from web browsers including browsing history, downloads, and stored passwords. Supports Chrome, Edge, Brave, and Firefox browsers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "browser": {
                        "type": "string",
                        "description": "Browser to analyze. Options: chrome, edge, brave, firefox",
                        "enum": ["chrome", "edge", "brave", "firefox"]
                    },
                    "artifact_type": {
                        "type": "string",
                        "description": "Type of artifact to extract. Options: history (browsing history), downloads (download history), passwords (stored credentials), all (everything)",
                        "enum": ["history", "downloads", "passwords", "all"]
                    }
                },
                "required": ["browser", "artifact_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_network_pcap",
            "description": "Analyze PCAP/PCAPNG network capture files to extract forensic artifacts including network summary, credentials, HTTP traffic, file transfers, and suspicious IPs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "analysis_type": {
                        "type": "string",
                        "description": "Type of analysis to perform. Options: summary (packet statistics and top talkers), credentials (extract login credentials), files (detect file transfers), http_traffic (extract HTTP requests), suspicious_ips (find non-private IPs with credential traffic)",
                        "enum": ["summary", "credentials", "files", "http_traffic", "suspicious_ips"]
                    }
                },
                "required": ["analysis_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_file_metadata",
            "description": "Extract comprehensive metadata from files including basic file info, cryptographic hashes (MD5, SHA1, SHA256), EXIF data for images, and file signatures for forensic analysis and integrity verification.",
            "parameters": {
                "type": "object",
                "properties": {
                    "metadata_type": {
                        "type": "string",
                        "description": "Type of metadata to extract. Options: basic (file size, type, extension), hashes (MD5, SHA1, SHA256), exif (EXIF data for images), all (complete metadata including everything)",
                        "enum": ["basic", "hashes", "exif", "all"]
                    }
                },
                "required": ["metadata_type"]
            }
        }
    }
]

# Function to execute a tool call
def execute_tool(tool_call, file_content: bytes, ext: str, filename: str = "unknown"):
    func_name = tool_call.function.name
    args = json.loads(tool_call.function.arguments) if tool_call.function.arguments else {}
    print("Tool Called:", func_name, "Args:", args)
    if func_name == "file_signature_analysis":
        result = file_signature_analysis(file_content, ext)
    elif func_name == "carve_jpegs_from_doc":
        result = carve_jpegs_from_doc(file_content)
    elif func_name == "capture_disk_image":
        source_device = args.get("source_device")
        if not source_device:
            result = "Error: source_device parameter is required."
        else:
            result = capture_disk_image(source_device)
    elif func_name == "recover_deleted_files":
        result = recover_deleted_files(file_content)
    elif func_name == "analyze_windows_registry":
        action = args.get("action")
        if not action:
            result = "Error: action parameter is required."
        else:
            result = analyze_windows_registry(action)
    elif func_name == "analyze_browser_forensics":
        browser = args.get("browser")
        artifact_type = args.get("artifact_type")
        if not browser or not artifact_type:
            result = "Error: browser and artifact_type parameters are required."
        else:
            result = analyze_browser_forensics(browser, artifact_type)
    elif func_name == "analyze_network_pcap":
        analysis_type = args.get("analysis_type")
        if not analysis_type:
            result = "Error: analysis_type parameter is required."
        else:
            result = analyze_network_pcap(file_content, analysis_type)
    elif func_name == "extract_file_metadata":
        metadata_type = args.get("metadata_type")
        if not metadata_type:
            result = "Error: metadata_type parameter is required."
        else:
            result = extract_file_metadata(file_content, filename, metadata_type)
    else:
        result = "Unknown function."
    print("Tool Result:", result)
    return {
        "role": "tool",
        "tool_call_id": tool_call.id,
        "name": func_name,
        "content": result
    }, func_name, args, result

# Main function to process query - now returns detailed info for logging
def process_forensics_query(query: str, file_content: bytes, ext: str, filename: str = "unknown"):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a computer forensics assistant. For queries about file analysis, "
                "always use the provided tools (file_signature_analysis, carve_jpegs_from_doc, capture_disk_image, recover_deleted_files, analyze_windows_registry, analyze_browser_forensics, analyze_network_pcap, extract_file_metadata) "
                "to process the uploaded file or device. For capture_disk_image, use the source_device from the query. "
                "After receiving tool results, summarize them in a concise natural language response. "
                "If no tool is applicable, explain why the query cannot be processed."
            )
        },
        {
            "role": "user",
            "content": f"File uploaded: {filename} with extension: {ext}\nQuery: {query}"
        }
    ]
    
    tool_info = {
        'tool_called': None,
        'tool_arguments': None,
        'tool_result': None
    }
    
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.1
        )
        print("Initial Response:", response)
    except Exception as e:
        return f"API Error: {str(e)}", tool_info
    
    response_message = response.choices[0].message
    tool_calls = response_message.tool_calls
    
    if tool_calls:
        messages.append(response_message)
        tool_results = []
        for tool_call in tool_calls:
            # tool_response, func_name, args, result = execute_tool(tool_call, file_content, ext)
            # Extract filename from the user's query context if available
            filename = "evidence_file" + ext
            tool_response, func_name, args, result = execute_tool(tool_call, file_content, ext, filename)
            messages.append(tool_response)
            tool_results.append(tool_response["content"])
            
            # Store tool info for logging (last tool if multiple)
            tool_info['tool_called'] = func_name
            tool_info['tool_arguments'] = json.dumps(args)
            tool_info['tool_result'] = result
        
        try:
            final_response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            print("Final Response:", final_response)
            content = final_response.choices[0].message.content
            return (content if content else tool_results[0]), tool_info
        except Exception as e:
            return f"Final API Error: {str(e)}", tool_info
    else:
        return (response_message.content or "Error: No tool called and no direct response provided."), tool_info

def load_chat_history(session, evidence_id, current_user_id):
    """Load chat history from access logs for a specific evidence file"""
    logs = session.query(AccessLog).filter(
        AccessLog.evidence_id == evidence_id,
        AccessLog.operation == 'analyze_evidence',
        AccessLog.query.isnot(None)
    ).order_by(AccessLog.timestamp).all()
    
    chat_history = []
    for log in logs:
        # Add user query
        chat_history.append({
            "role": "user",
            "content": log.query,
            "timestamp": log.timestamp,
            "user": log.user.username
        })
        
        # Add assistant response
        if log.llm_response:
            chat_history.append({
                "role": "assistant",
                "content": log.llm_response,
                "timestamp": log.timestamp,
                "tool_called": log.tool_called
            })
    
    return chat_history

# Streamlit UI
st.title('Computer Forensics Prototype - Chain of Custody System')

session = Session()
init_data(session)

# Initialize session state for active evidence analysis
if 'active_evidence_id' not in st.session_state:
    st.session_state.active_evidence_id = None

if 'chat_messages' not in st.session_state:
    st.session_state.chat_messages = {}

if 'chat_loaded' not in st.session_state:
    st.session_state.chat_loaded = {}

# Login
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
    st.session_state.is_admin = False

if not st.session_state.user_id:
    st.subheader('Login')
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    if st.button('Login'):
        user = session.query(User).filter_by(username=username).first()
        if user and verify_password(user.password_hash, password):
            st.session_state.user_id = user.id
            st.session_state.is_admin = user.is_admin
            st.success('Logged in!')
            st.rerun()
        else:
            st.error('Invalid credentials')
else:
    user_id = st.session_state.user_id
    is_admin = st.session_state.is_admin
    user = session.query(User).filter_by(id=user_id).first()
    st.sidebar.write(f'Logged in as: {user.username} {"(Admin)" if is_admin else ""}')
    if st.sidebar.button('Logout'):
        st.session_state.user_id = None
        st.session_state.is_admin = False
        st.session_state.active_evidence_id = None
        st.session_state.chat_messages = {}
        st.session_state.chat_loaded = {}
        st.rerun()
    
    # Check access for cases
    def get_accessible_cases(sess, uid, admin):
        if admin:
            return sess.query(Case).all()
        officer_cases = sess.query(Case).filter(Case.enquiring_officer_id == uid).all()
        team_cases = [tm.case for tm in sess.query(TeamMember).filter_by(user_id=uid).all()]
        accessible = set(officer_cases + team_cases)
        return list(accessible)
    
    accessible_cases = get_accessible_cases(session, user_id, is_admin)
    
    # Sidebar case selection
    st.sidebar.header("Cases")
    case_options = ["Select a Case"] + [f"{case.id}: {case.title}" for case in accessible_cases]
    selected_case_option = st.sidebar.selectbox("Choose a Case", case_options, key="case_select")
    selected_case = None
    if selected_case_option != "Select a Case":
        case_id = int(selected_case_option.split(":")[0])
        selected_case = session.query(Case).filter_by(id=case_id).first()
    
    # Main content area for case details
    if selected_case:
        st.header(f"Case: {selected_case.title} (ID: {selected_case.id})")
        st.write(f"**Description:** {selected_case.description}")
        st.write(f"**Enquiring Officer:** {selected_case.enquiring_officer.username if selected_case.enquiring_officer else 'N/A'}")
        
        if st.button('View Details', key=f'view_{selected_case.id}'):
            log_access(session, user_id, selected_case.id, operation='view_case')
            st.success('Case details viewed (logged).')
        
        evidences = selected_case.evidences
        if evidences:
            st.subheader("Evidences")
            for evidence in evidences:
                st.write(f"- **{evidence.file_name}** (Uploaded: {evidence.uploaded_at})")
                metadata = json.loads(evidence.evidence_metadata) if evidence.evidence_metadata else {}
                st.write(f"  **Metadata:** {metadata}")
                
                # Button to start/stop analysis
                col1, col2 = st.columns([1, 4])
                with col1:
                    if st.button(f'Analyze', key=f'analyze_{evidence.id}'):
                        if st.session_state.active_evidence_id == evidence.id:
                            # Close the chat
                            st.session_state.active_evidence_id = None
                        else:
                            # Open the chat for this evidence and load history
                            st.session_state.active_evidence_id = evidence.id
                            
                            # Load chat history from access logs if not already loaded
                            if evidence.id not in st.session_state.chat_loaded:
                                chat_history = load_chat_history(session, evidence.id, user_id)
                                st.session_state.chat_messages[evidence.id] = chat_history
                                st.session_state.chat_loaded[evidence.id] = True
                            
                            log_access(session, user_id, selected_case.id, evidence.id, 'open_analysis')
                        st.rerun()
                
                # Display chat interface if this evidence is active
                if st.session_state.active_evidence_id == evidence.id:
                    if evidence.id not in st.session_state.chat_messages:
                        chat_history = load_chat_history(session, evidence.id, user_id)
                        st.session_state.chat_messages[evidence.id] = chat_history
                        st.session_state.chat_loaded[evidence.id] = True
                    
                    st.markdown(f"**Chat for {evidence.file_name}**")
                    st.caption(f"💬 {len([m for m in st.session_state.chat_messages[evidence.id] if m['role'] == 'user'])} previous queries in history")
                    
                    # Display chat history
                    for message in st.session_state.chat_messages[evidence.id]:
                        if message["role"] == "user":
                            with st.chat_message("user"):
                                st.markdown(message["content"])
                                if "user" in message and message["user"] != user.username:
                                    st.caption(f"*Asked by {message['user']} at {message.get('timestamp', 'N/A')}*")
                        else:
                            with st.chat_message("assistant"):
                                st.markdown(message["content"])
                                if "tool_called" in message and message["tool_called"]:
                                    st.caption(f"🔧 Tool used: {message['tool_called']}")
                    
                    # Chat input
                    query = st.chat_input(f"Ask about {evidence.file_name}", key=f"chat_input_{evidence.id}")
                    if query:
                        # Add user message
                        with st.chat_message("user"):
                            st.markdown(query)
                        st.session_state.chat_messages[evidence.id].append({
                            "role": "user", 
                            "content": query,
                            "user": user.username,
                            "timestamp": datetime.datetime.utcnow()
                        })
                        
                        # Process the query
                        file_path = evidence.file_path
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                        ext = os.path.splitext(evidence.file_name)[1]
                        
                        with st.spinner("Analyzing..."):
                            result, tool_info = process_forensics_query(query, file_content, ext, evidence.file_name)
                        
                        # Add assistant response
                        with st.chat_message("assistant"):
                            st.markdown(result)
                            if tool_info['tool_called']:
                                st.caption(f"🔧 Tool used: {tool_info['tool_called']}")
                        
                        st.session_state.chat_messages[evidence.id].append({
                            "role": "assistant", 
                            "content": result,
                            "tool_called": tool_info['tool_called'],
                            "timestamp": datetime.datetime.utcnow()
                        })
                        
                        # Log the detailed access with chain of custody info
                        log_access(
                            session, 
                            user_id, 
                            selected_case.id, 
                            evidence.id, 
                            'analyze_evidence',
                            query=query,
                            tool_called=tool_info['tool_called'],
                            tool_arguments=tool_info['tool_arguments'],
                            tool_result=tool_info['tool_result'],
                            llm_response=result
                        )
                        
                        st.rerun()
                
                # Display Chain of Custody logs for this evidence
                with st.expander(f"📋 Chain of Custody - {evidence.file_name}"):
                    evidence_logs = session.query(AccessLog).filter_by(evidence_id=evidence.id).order_by(AccessLog.timestamp.desc()).all()
                    
                    if not evidence_logs:
                        st.info("No access logs for this evidence yet.")
                    else:
                        for log in evidence_logs:
                            st.markdown("---")
                            col1, col2 = st.columns([2, 3])
                            
                            with col1:
                                st.write(f"**👤 User:** {log.user.username}")
                                st.write(f"**📅 Time:** {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                                st.write(f"**🔧 Operation:** {log.operation}")
                            
                            with col2:
                                if log.query:
                                    st.write(f"**❓ Query:** {log.query}")
                                if log.tool_called:
                                    st.write(f"**🛠️ Tool Called:** {log.tool_called}")
                                if log.tool_arguments:
                                    try:
                                        args = json.loads(log.tool_arguments)
                                        if args:
                                            st.write(f"**⚙️ Arguments:** {args}")
                                    except:
                                        pass
                                if log.tool_result:
                                    with st.expander("View Tool Result"):
                                        st.text(log.tool_result[:500] + "..." if len(log.tool_result) > 500 else log.tool_result)
                                if log.llm_response:
                                    with st.expander("View LLM Response"):
                                        st.write(log.llm_response)
        
        st.subheader("Team Members")
        team_members = [tm.member.username for tm in selected_case.team_members]
        st.write(f"{', '.join(team_members) if team_members else 'None'}")
        
        # Case-level access logs
        if is_admin or (selected_case.enquiring_officer_id == user_id):
            with st.expander('📊 Case Access Logs'):
                logs = session.query(AccessLog).filter_by(case_id=selected_case.id).order_by(AccessLog.timestamp.desc()).all()
                
                if not logs:
                    st.info("No access logs for this case yet.")
                else:
                    for log in logs:
                        ev_name = log.evidence.file_name if log.evidence else 'Case Level'
                        st.write(f"**{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}** - "
                                f"User: *{log.user.username}* | "
                                f"Operation: *{log.operation}* | "
                                f"Target: *{ev_name}*")
                        
                        if log.query:
                            st.write(f"  └─ Query: {log.query}")
                        if log.tool_called:
                            st.write(f"  └─ Tool: {log.tool_called}")
    else:
        st.write("Please select a case from the sidebar to view details.")

    if is_admin:
        st.subheader('🔍 All Access Logs (Admin View)')
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            filter_user = st.selectbox("Filter by User", ["All"] + [u.username for u in session.query(User).all()])
        with col2:
            filter_case = st.selectbox("Filter by Case", ["All"] + [f"{c.id}: {c.title}" for c in session.query(Case).all()])
        with col3:
            filter_operation = st.selectbox("Filter by Operation", ["All", "view_case", "analyze_evidence", "open_analysis"])
        
        # Build query
        query = session.query(AccessLog).order_by(AccessLog.timestamp.desc())
        
        if filter_user != "All":
            user_obj = session.query(User).filter_by(username=filter_user).first()
            if user_obj:
                query = query.filter_by(user_id=user_obj.id)
        
        if filter_case != "All":
            case_id = int(filter_case.split(":")[0])
            query = query.filter_by(case_id=case_id)
        
        if filter_operation != "All":
            query = query.filter_by(operation=filter_operation)
        
        all_logs = query.limit(100).all()
        
        st.write(f"Showing {len(all_logs)} logs (max 100)")
        
        for log in all_logs:
            ev_name = log.evidence.file_name if log.evidence else 'Case Level'
            
            with st.expander(f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {log.user.username} - {log.operation} on {ev_name}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**User:** {log.user.username}")
                    st.write(f"**Case ID:** {log.case_id}")
                    st.write(f"**Evidence:** {ev_name}")
                    st.write(f"**Operation:** {log.operation}")
                    st.write(f"**Timestamp:** {log.timestamp}")
                
                with col2:
                    if log.query:
                        st.write(f"**Query:**")
                        st.info(log.query)
                    
                    if log.tool_called:
                        st.write(f"**Tool Called:** `{log.tool_called}`")
                    
                    if log.tool_arguments:
                        st.write(f"**Tool Arguments:**")
                        try:
                            args = json.loads(log.tool_arguments)
                            st.json(args)
                        except:
                            st.text(log.tool_arguments)
                
                if log.tool_result:
                    st.write("**Tool Result:**")
                    with st.expander("View Full Result"):
                        st.text(log.tool_result)
                
                if log.llm_response:
                    st.write("**LLM Response:**")
                    st.markdown(log.llm_response)

session.close()


