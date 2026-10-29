import hashlib
import hmac
import os
import unicodedata
import base64

CURRENT_N = 16384
CURRENT_R = 8
CURRENT_P = 5

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _b64_decode(s: str) -> bytes | None:
    try:
        padding = 4 - (len(s) % 4)
        if padding < 4:
            s += '=' * padding
        return base64.urlsafe_b64decode(s.encode('ascii'))
    except Exception:
        return None

def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    norm_pw = unicodedata.normalize('NFKC', password)
    if not (8 <= len(norm_pw) <= 128):
        raise ValueError("Password length must be between 8 and 128 characters.")
    
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        norm_pw.encode('utf-8'),
        salt=salt,
        n=CURRENT_N,
        r=CURRENT_R,
        p=CURRENT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024
    )
    salt_b64 = _b64_encode(salt)
    hash_b64 = _b64_encode(dk)
    return f"scrypt${CURRENT_N}${CURRENT_R}${CURRENT_P}${salt_b64}${hash_b64}"

def _parse_stored(stored: str):
    if not isinstance(stored, str):
        return None
    parts = stored.split('$')
    if len(parts) != 6:
        return None
    scheme, n_str, r_str, p_str, salt_b64, hash_b64 = parts
    if scheme != "scrypt":
        return None
    
    # Prevent extremely long strings to avoid DoS on int conversion
    if len(n_str) > 7 or len(r_str) > 4 or len(p_str) > 4:
        return None

    try:
        n = int(n_str)
        r = int(r_str)
        p = int(p_str)
    except ValueError:
        return None
        
    if not (2 <= n <= 2**20 and (n & (n - 1)) == 0):
        return None
        
    if not (1 <= r <= 32):
        return None
        
    if not (1 <= p <= 16):
        return None
        
    salt_bytes = _b64_decode(salt_b64)
    if salt_bytes is None or len(salt_bytes) < 16:
        return None
        
    hash_bytes = _b64_decode(hash_b64)
    if hash_bytes is None or len(hash_bytes) != 32:
        return None
        
    return n, r, p, salt_bytes, hash_bytes

def verify_password(password: str, stored: str) -> bool:
    if not isinstance(password, str):
        return False
    parsed = _parse_stored(stored)
    if parsed is None:
        return False
    n, r, p, salt_bytes, expected_hash = parsed
    
    try:
        norm_pw = unicodedata.normalize('NFKC', password)
        if not (8 <= len(norm_pw) <= 128):
            return False
            
        computed_hash = hashlib.scrypt(
            norm_pw.encode('utf-8'),
            salt=salt_bytes,
            n=n,
            r=r,
            p=p,
            dklen=32,
            maxmem=64 * 1024 * 1024
        )
        return hmac.compare_digest(computed_hash, expected_hash)
    except Exception:
        return False

def needs_rehash(stored: str) -> bool:
    parsed = _parse_stored(stored)
    if parsed is None:
        return True
    n, r, p, _, _ = parsed
    if n < CURRENT_N or r < CURRENT_R or p < CURRENT_P:
        return True
    return False
