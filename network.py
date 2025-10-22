import os
import re
import json
import base64
from collections import defaultdict, Counter
from scapy.all import rdpcap, TCP, Raw, IP, IPv6
from datetime import datetime

# -----------------------
# Helpers
# -----------------------
def iso(ts):
    try:
        return datetime.utcfromtimestamp(float(ts)).isoformat() + "Z"
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

def sanitize_filename(name):
    return re.sub(r'[^A-Za-z0-9_\-\.]', '_', name)[:200]

# -----------------------
# TCP stream assembly
# -----------------------
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

# -----------------------
# HTTP parsing helpers
# -----------------------
_http_request_re = re.compile(br'^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/1\.[01]', re.I | re.M)
_http_response_re = re.compile(br'^HTTP/1\.[01]\s+(\d{3})\s+([^\r\n]+)', re.I | re.M)
_header_split_re = re.compile(br'\r\n\r\n', re.M)
_header_line_re = re.compile(br'(?P<name>[^:\r\n]+):\s*(?P<value>[^\r\n]+)', re.I)

def parse_http_messages(stream_bytes):
    messages = []
    i = 0
    data = stream_bytes
    L = len(data)
    while i < L:
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
            body_end = body_start + next_header.start() if next_header else L
        else:
            body_end = min(body_start + content_length, L)
        body = data[body_start:body_end]
        message = {"type": "request" if kind=='req' else "response",
                   "start": start_pos, "end": body_end,
                   "headers": headers, "body": body}
        messages.append(message)
        i = body_end
    return messages

# -----------------------
# Credential detection
# -----------------------
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
        for keypair in (('username','password'), ('user','pass'), ('user','password'), ('login','password')):
            ukey, pkey = keypair
            if ukey in txt and pkey in txt:
                m = re.search(r'([&\?]|^)' + re.escape(ukey) + r'=([^&\s]+).*?' + re.escape(pkey) + r'=([^&\s]+)', txt, re.I | re.S)
                if m:
                    creds.append({'type':'http_form', 'user':m.group(2), 'pass':m.group(3)})
        if 'password=' in txt.lower():
            m = re.search(r'password=([^&\s]+)', txt, re.I)
            if m:
                creds.append({'type':'http_password_field', 'password': m.group(1)})
    except:
        pass
    return creds

# -----------------------
# File saving
# -----------------------
import mimetypes
import zipfile
import io

def detect_file_extension(data):
    """Detect file type from magic bytes or content signatures."""

    # --- Direct magic-byte detection ---
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return ".png"
    elif data.startswith(b'\xff\xd8\xff'):
        return ".jpg"
    elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
        return ".gif"
    elif data.startswith(b'%PDF-'):
        return ".pdf"
    elif data.startswith(b'II*\x00') or data.startswith(b'MM\x00*'):
        return ".tiff"
    elif data.startswith(b'\x42\x4D'):
        return ".bmp"
    elif data.startswith(b'\x25\x21PS'):
        return ".ps"
    elif data.startswith(b'\x7FELF'):
        return ".elf"
    elif data.startswith(b'MZ'):
        return ".exe"
    elif data.startswith(b'\x52\x61\x72\x21\x1A\x07\x00'):
        return ".rar"

    # --- ZIP-based format detection ---
    if data.startswith(b'PK\x03\x04'):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                if any(n.startswith('word/') for n in names):
                    return ".docx"
                elif any(n.startswith('xl/') for n in names):
                    return ".xlsx"
                elif any(n.startswith('ppt/') for n in names):
                    return ".pptx"
                elif any(n.startswith('META-INF/') and n.endswith('.SF') for n in names):
                    if any(n.startswith('classes.dex') for n in names):
                        return ".apk"
                    return ".jar"
                elif any(n.startswith('AndroidManifest.xml') for n in names):
                    return ".apk"
                else:
                    return ".zip"
        except zipfile.BadZipFile:
            return ".zip"

    # --- Fallback: try MIME type guess ---
    mime = mimetypes.guess_type("dummy", strict=False)[0]
    if mime:
        ext = mimetypes.guess_extension(mime)
        if ext:
            return ext

    # Default fallback
    return ".bin"


def save_http_body(headers, body, out_dir, default_prefix="file"):
    """Save extracted HTTP body with detected file extension."""
    cdisp = headers.get('content-disposition', '')
    ctype = headers.get('content-type', '')
    filename = None

    # Try extracting filename from Content-Disposition
    if cdisp:
        m = re.search(r'filename="?([^";]+)"?', cdisp)
        if m:
            filename = m.group(1)

    # Try from Content-Location
    if not filename and 'content-location' in headers:
        filename = os.path.basename(headers['content-location'])

    # Detect extension from data
    ext = detect_file_extension(body)

    if not filename:
        filename = f"{default_prefix}{ext}"
    else:
        # Add extension if missing
        if not os.path.splitext(filename)[1]:
            filename += ext

    filename = sanitize_filename(filename)

    # Determine if file should be saved (skip plain text)
    text_like = all(32 <= b < 127 or b in (9, 10, 13) for b in body[:512])
    should_save = (not text_like) or ('application' in ctype) or ('attachment' in cdisp.lower())

    if not should_save:
        return None

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, filename)
    base, extf = os.path.splitext(out_path)
    counter = 1
    while os.path.exists(out_path):
        out_path = f"{base}_{counter}{extf}"
        counter += 1

    try:
        with open(out_path, 'wb') as f:
            f.write(body)
        print(f"[+] Extracted: {filename}")
        return out_path
    except Exception as e:
        print(f"Error saving {filename}: {e}")
        return None

# -----------------------
# Main analysis function
# -----------------------
def analyze_pcap(pcap_path=r"C:\Users\vishn\Downloads\captures.pcapng", output_dir="extracted_files"):
    if not os.path.exists(pcap_path):
        return {"error": "pcap file not found"}
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return {"error": f"failed to read pcap: {e}"}

    summary = {
        "pcap_path": pcap_path,
        "total_packets": len(packets),
        "start_time": iso(packets[0].time) if packets else None,
        "end_time": iso(packets[-1].time) if packets else None,
        "unique_ips": [],
        "top_talkers": [],
        "tcp_streams": 0,
        "suspicious_ips": [],
        "credentials": [],
        "file_transfers": []
    }

    ip_counter = Counter()
    for pkt in packets:
        try:
            if IP in pkt:
                ip_counter[pkt[IP].src] += 1
        except:
            continue
    summary["unique_ips"] = list(ip_counter.keys())
    summary["top_talkers"] = ip_counter.most_common(10)

    streams = build_tcp_streams(packets)
    summary["tcp_streams"] = len(streams)

    suspicious_ips = set()
    for (src,dst,sport,dport), entries in streams.items():
        entries.sort(key=lambda x: x[0])
        blob = b"".join(p for _,p in entries)
        http_msgs = parse_http_messages(blob)
        if http_msgs:
            for msg in http_msgs:
                if msg["type"] == "response":
                    saved = save_http_body(msg["headers"], msg["body"], output_dir, default_prefix=f"{src}_{dst}_{sport}_{dport}")
                    if saved:
                        summary["file_transfers"].append({"protocol":"HTTP","src":src,"dst":dst,"saved_path":saved,"time":iso(entries[0][0])})
                creds = detect_credentials_in_http(msg.get("headers",{}), msg.get("body",b""))
                for c in creds:
                    summary["credentials"].append({"protocol":"HTTP","src":src,"dst":dst,"credential":c,"time":iso(entries[0][0])})
                    suspicious_ips.add(src)
                    suspicious_ips.add(dst)

    summary["suspicious_ips"] = list(suspicious_ips)
    return summary

# -----------------------
# Example usage
# -----------------------
if __name__ == "__main__":
    result = analyze_pcap()
    print(json.dumps(result, indent=2))
