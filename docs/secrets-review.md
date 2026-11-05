# Structured Secrets Review and TC-CF-001

## Pipeline

WCA uses bounded static discovery of eligible configuration files and PE printable strings. It recognizes `.env`, `.env.*`, `.env-*`, `.config`, `.json`, `.xml`, `.pem`, `.key`, `.p8` and existing script/config extensions. Candidate fields are classified by credential-bearing names and non-placeholder values. Ordinary Qt HTML and public identifiers such as GA measurement IDs are excluded from credential findings. Generic high entropy alone is not a proof of a secret.

Complete PEM key blocks are recognized offline and parsed with the required Python `cryptography` dependency. WCA reports **VALID_KEY**, **ENCRYPTED_NOT_DECRYPTED**, **INVALID_OR_UNSUPPORTED**, **MARKER_ONLY**, or **PARSER_UNAVAILABLE** as applicable. For validated keys, it can record algorithm, key size and SHA-256 of public SubjectPublicKeyInfo DER (not of the private key). Multiple occurrences of the same public fingerprint are counted and remain separate source locations for review. The fingerprint is not proof of key compromise or exploitability.

## Tester-only original viewer

TC-CF-001 automatically returns the full original matched value when a tester selects an indicator from an integrity-verified assessment. Original values are never saved into `secrets_review.txt`, local review-state JSON, Client Appendix, tool logs or browser persistent storage by WCA. **Authorized tester use is intentional:** values become visible in the local browser, browser developer tools and screenshots. Clipboard copying is explicit.

Only original files inside the integrity-verified `working/extracted_installer` area can be read/opened automatically. The viewer rejects missing, symlinked and traversal/outside sources. Text context is limited to nearby numbered lines, and PE context is bounded near the recorded byte offset. Full PEM values are returned separately from the context window. Open File Location uses Explorer selection; **it never runs a DLL or EXE**. Sources outside the protected extraction are manual.

## Interpretation

- A syntactically parseable private key is **structurally valid**, but does not establish intended use, key ownership, reachability, or exploitability.
- A token-looking string or API key assignment is a **potential credential** pending tester validation.
- A public identifier, placeholder or ordinary framework label is not a secret merely because it contains the word `key`.
- Detection counts and WCR statuses are **not** counts of confirmed vulnerabilities. Manual TC and Guided Review decisions remain independent and notes optional.
- Limits, unsupported formats and analysis-version changes must be disclosed. The same app re-scanned with a different WCA version can legitimately produce different indicator counts.

## Regressions

Run `python -m unittest discover -s tests -v` for the focused portable corpus. Real application review is still required to establish impact.
