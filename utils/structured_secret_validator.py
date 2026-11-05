"""Offline, bounded key-block recognition and public-key metadata only.

Private bytes are processed in memory. Persist only type, validity, size,
public-key fingerprint, and location; never a secret-derived password hash.
"""
from __future__ import annotations
import hashlib
import re

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None

MAX_PEM_BYTES = 65536
_PEM_BYTES = re.compile(rb'-----BEGIN (?P<label>RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY|ENCRYPTED PRIVATE KEY|PRIVATE KEY)-----\s*?[\s\S]{0,60000}?-----END (?P=label)-----')
_START = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')


def inspect_pem(block: bytes, label: str) -> dict:
    if len(block) > MAX_PEM_BYTES:
        return {'validation': 'TOO_LARGE', 'algorithm': '', 'key_bits': '', 'public_fingerprint': ''}
    if serialization is None:
        return {'validation': 'PARSER_UNAVAILABLE', 'algorithm': '', 'key_bits': '', 'public_fingerprint': ''}
    try:
        key = (serialization.load_ssh_private_key(block, password=None)
               if label == 'OPENSSH PRIVATE KEY'
               else serialization.load_pem_private_key(block, password=None))
        public = key.public_key()
        data = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'validation': 'VALID_KEY', 'algorithm': type(key).__name__.replace('PrivateKey', '').replace('_', ''),
                'key_bits': getattr(key, 'key_size', ''),
                'public_fingerprint': hashlib.sha256(data).hexdigest()}
    except TypeError as exc:
        # Correctly encoded encrypted keys request a password. Do not supply one.
        if 'password' in str(exc).lower() or 'encrypted' in str(exc).lower():
            return {'validation': 'ENCRYPTED_NOT_DECRYPTED', 'algorithm': '',
                    'key_bits': '', 'public_fingerprint': ''}
    except (ValueError, Exception):
        pass
    return {'validation': 'INVALID_OR_UNSUPPORTED', 'algorithm': '',
            'key_bits': '', 'public_fingerprint': ''}


def pem_candidates(blob: bytes):
    """Yield complete blocks and standalone markers, at raw byte offsets."""
    occupied=[]
    for match in _PEM_BYTES.finditer(blob):
        occupied.append((match.start(), match.end()))
        yield match.start(), match.end(), match.group('label').decode('ascii'), inspect_pem(match.group(),match.group('label').decode('ascii'))
    for match in _START.finditer(blob):
        if any(a<=match.start()<b for a,b in occupied):
            continue
        yield match.start(),match.end(),'MARKER',{'validation':'MARKER_ONLY','algorithm':'','key_bits':'','public_fingerprint':''}
