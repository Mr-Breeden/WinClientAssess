"""Evidence-backed confidence, never an exploitability or vulnerability score."""
from __future__ import annotations


def candidate_confidence(kind: str, validation: str) -> str:
    if validation == 'VALID_KEY':
        return 'HIGH'
    if validation == 'ENCRYPTED_NOT_DECRYPTED':
        return 'MEDIUM'
    if validation in ('INVALID_OR_UNSUPPORTED', 'MARKER_ONLY', 'PARSER_UNAVAILABLE'):
        return 'LOW'
    if kind in ('AWS access key', 'Bearer token'):
        return 'MEDIUM'
    if kind in ('XML credential element', 'JSON credential property', 'Named credential assignment',
                'Connection string'):
        return 'MEDIUM'
    return 'LOW'
