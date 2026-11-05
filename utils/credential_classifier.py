"""Classify candidate fields, not generic UI strings; no secret values persisted."""
from __future__ import annotations
import re

SENSITIVE = ('password', 'passwd', 'passphrase', 'secret', 'token', 'apikey',
             'accesskey', 'privatekey', 'masterkey', 'encryptionkey',
             'deploymentkey', 'licenseblob', 'connectionstring', 'credential')
PUBLIC_FIELDS = ('measurementid', 'analyticsid', 'trackingid', 'publickey',
                 'accesskeyid', 'keysize', 'keylength', 'logpasswords', 'logsecrets')
PLACEHOLDERS = {'', 'true', 'false', 'yes', 'no', 'none', 'null', 'enabled',
                'disabled', 'unknown', 'undefined', 'example', 'changeme',
                'replace_me', 'your_key_here', 'placeholder', 'notset', 'todo',
                'password', 'secret', 'token', '<secret>', 'xxx', 'xxxx', '[hidden]', '[redacted]', '<redacted>', '[masked]', '<masked>', 'your_password_here', 'your_secret_here', 'password_here'}


def credential_field(name: str, value: str) -> bool:
    key = re.sub('[^a-z0-9]', '', str(name).casefold())
    if any(excluded in key for excluded in PUBLIC_FIELDS):
        return False
    if not any(word in key for word in SENSITIVE):
        return False
    value = str(value).strip().strip('"\'')
    if len(value) < 4 or value.casefold() in PLACEHOLDERS:
        return False
    if re.fullmatch(r'[\*#xX•●]{3,}', value) or re.fullmatch(r'[\[<](?:hidden|redacted|masked|removed|secret|password)[\]>]', value, re.I):
        return False
    # A binary's printable strings frequently contain C++/Qt symbol fragments.
    if re.match(r'^:(?:read|write|hasCredentials|loadPrivateKey|[A-Za-z_]\w*)\s*\(', value) or re.search(r'(?:QString|QByteArray|Password)\s*[*&]|\bconst\b|[();]', value):
        return False
    if re.fullmatch(r'(?:%\d+|\$\{[^}]+\}|\{\{[^}]+\}\})', value):
        return False
    return True


def evidence_reason(kind: str, *, validation: str = 'UNVALIDATED') -> str:
    if kind == 'Structured private key':
        return 'Complete PEM private-key block identified; cryptographic structure inspected locally.'
    if kind == 'Encrypted private key':
        return 'Complete encrypted PEM private-key block identified; no decryption attempted.'
    if kind == 'Private key marker':
        return 'Private-key opening marker observed; no complete parseable key established.'
    if kind in ('XML credential element', 'JSON credential property', 'Named credential assignment',
                'Generic password assignment', 'Generic secret assignment'):
        return 'Credential-related field name with a non-placeholder assigned value.'
    if kind == 'AWS access key':
        return 'Access-key identifier shape matched; no service validity or secret half proven.'
    if kind == 'Bearer token':
        return 'Bearer-style token syntax detected; usability was not tested.'
    if kind == 'Connection string':
        return 'Connection string contains a password field; impact requires manual validation.'
    return 'Potential credential syntax matched; manual validation required.'
