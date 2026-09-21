# Security Policy

CyberSentinel is a defensive/Blue Team educational project. It analyzes plain text `.log` and `.txt` files only.

## Security practices included

- No execution of user-provided code, shell commands, or payloads
- Login with server-side session cookies
- CSRF protection on forms and API upload endpoint
- File extension and size validation
- Binary file rejection
- Path traversal protection through safe server-generated filenames
- Flask debug mode disabled
- Security headers
- SQLite persistence for analysis history
- Audit logs for login, logout, upload, and analysis events
- Docker container runs as a non-root user
- CI workflow with tests, linting, and dependency audit

## Production notes

Use HTTPS, set strong environment variables, keep dependencies patched, and deploy behind Nginx or another trusted reverse proxy.
