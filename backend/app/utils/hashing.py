import hashlib
from pathlib import Path


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def compute_bytes_hash(data: bytes, algorithm: str = "sha256") -> str:
    hash_func = hashlib.new(algorithm)
    hash_func.update(data)
    return hash_func.hexdigest()


def sanitize_filename(filename: str) -> str:
    import re
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('. ')
    return filename[:255]