# TrustVault Threat Model

## Status

Initial threat inventory. Mitigations are planned and must not be considered implemented until verified.

| Threat | Planned mitigation | Verification |
|---|---|---|
| Unauthorized document ID access | Server-side document-level authorization | Cross-user API integration tests |
| Direct storage access | Private storage outside public web directories | Attempt direct HTTP access |
| Revoked permission reused | Check current grants on each new request | Revoke, then attempt another download |
| Viewer privilege escalation | Derive roles from trusted server-side identity | Manipulate role fields in requests |
| Search result leakage | Filter results by authorization | Search as an unauthorized user |
| Audit record tampering | Restrict writes and implement tamper-evident verification | Attempt modification and verify integrity |
| Malicious file upload | Enforce size limits, allowlisted formats and safe storage names | Upload invalid and oversized files |
| Session theft or fixation | Secure cookies, session regeneration and invalidation | Test session lifecycle |
| Cross-site request forgery | CSRF protection for state-changing browser requests | Submit requests without valid tokens |
| SQL injection | Parameterized database queries | Test malicious search inputs |
| Account deactivation bypass | Revalidate active account status | Disable an account with an existing session |
| Concurrent revocation | Define and test authorization timing at the download boundary | Race a download against revocation |

## Known limitations

- Revocation cannot erase copies downloaded before access was removed.
- Tamper-evident hashing alone does not prevent a privileged attacker from rewriting the entire audit history.
- Production security depends on deployment configuration, secret management, backups and storage isolation.

## Review process

For each threat, record the implementation, an automated test, its actual result and any residual risk. Update this document as testing reveals additional attack paths.
