import os
import mimetypes
import hashlib
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS

def get_file_hash(file_path):
    """Generate MD5, SHA1, SHA256 hashes for file integrity verification."""
    hashes = {}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hashes["MD5"] = hashlib.md5(data).hexdigest()
            hashes["SHA1"] = hashlib.sha1(data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["Error"] = str(e)
    return hashes

def extract_exif_data(file_path):
    """Extract EXIF metadata if available (for images)."""
    exif_data = {}
    try:
        with Image.open(file_path) as img:
            info = img._getexif()
            if info:
                for tag, val in info.items():
                    tag_name = TAGS.get(tag, tag)
                    exif_data[tag_name] = val
    except Exception:
        pass
    return exif_data

def extract_metadata_from_file(file_path):
    """Extract complete metadata for a single file."""
    try:
        stat_info = os.stat(file_path)
        metadata = {
            "File Name": os.path.basename(file_path),
            "Full Path": os.path.abspath(file_path),
            "File Size (KB)": round(stat_info.st_size / 1024, 2),
            "Created": datetime.fromtimestamp(stat_info.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "Modified": datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "Accessed": datetime.fromtimestamp(stat_info.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
            "File Type": mimetypes.guess_type(file_path)[0] or "Unknown",
            "Permissions": oct(stat_info.st_mode)[-3:]
        }

        # Add hashes
        metadata.update(get_file_hash(file_path))

        # Add EXIF if applicable
        exif_data = extract_exif_data(file_path)
        if exif_data:
            metadata["EXIF Data"] = exif_data

        return metadata

    except Exception as e:
        return {"File": file_path, "Error": str(e)}

def extract_metadata(target_path):
    """
    Extract metadata from a single file or all files in a directory.
    """
    results = []

    if os.path.isfile(target_path):
        results.append(extract_metadata_from_file(target_path))

    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                results.append(extract_metadata_from_file(file_path))
    else:
        return {"error": "Invalid path provided"}

    return results

# Example usage
target = r"C:\Vishnu\Axios\Triathlon\theme.jpg"     # can be a single file or a directory
all_metadata = extract_metadata(target)
for entry in all_metadata:
    print(entry)