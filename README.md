# TrustVault 🔐

**Secure document sharing with a real audit trail**

TrustVault is a security-focused document management platform designed to ensure that confidential documents are accessible only to explicitly authorized users and that security-relevant activity is auditable.

## Project status

**Day 1 — Foundation and design**

The repository has been initialized. Authentication, document management, authorization enforcement, audit integrity, testing and deployment remain in progress until implemented and verified.

## Planned features

- Role-based authentication: administrator, owner and viewer
- Private document uploads and storage
- Per-document read and edit permissions
- Permission grants and revocation
- Secure document search and management
- Audit records for successful and denied operations
- Administrative activity dashboard
- Automated authorization and security tests

## Security principles

1. The server authorizes every document operation.
2. Files are stored privately and are never served directly from a public directory.
3. Access revocation prevents subsequent authorized requests from succeeding.
4. Security-relevant events are recorded and protected against unauthorized alteration.
5. Security claims must be supported by code and reproducible tests.

## Planned technology

- Node.js and Express
- EJS and CSS
- SQLite
- Automated HTTP integration tests

## Development

This project is being developed over seven days for a software security challenge.

See [THREATS.md](THREATS.md) for the initial threat model and [PROMPTS.md](PROMPTS.md) for the AI development diary.

## Current limitations

The application is not yet production-ready. Do not use it to store real confidential documents until security controls have been implemented and tested.

## License

MIT, if adopted for this project.
