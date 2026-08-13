# Security Policy

## Reporting Security Issues

If you discover a security vulnerability in PANDA, please report it responsibly.

### How to Report

Send an email to: **persandian@jatimprov.go.id**

Please include:
- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested mitigations (if known)

### What to Expect

- We will acknowledge receipt of your report within 48 hours
- We will provide a detailed response within 7 days
- We will notify you when a fix is released
- Your privacy will be respected; we will credit you unless you request otherwise

### Supported Versions

Only the latest version of PANDA receives security updates. Please upgrade to the latest version as soon as possible.

### Security Best Practices

1. **Key Management**: Never commit encryption keys to version control
2. **Token Security**: Protect PANDA access tokens as secrets
3. **TLS**: Always enable TLS for database connections
4. **Audit Logging**: Monitor decrypt_raw() calls for unusual activity
5. **Updates**: Keep PANDA SDK updated to the latest version

### Encryption Details

PANDA uses:
- **Algorithm**: AES-256-GCM (AEAD)
- **Nonce**: 12 bytes, randomly generated per encryption
- **Tag**: 16 bytes authentication tag
- **Key Size**: 256 bits (32 bytes)

All cryptographic operations use the Python Cryptography library, which is a wrapper around OpenSSL.
