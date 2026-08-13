# PANDA Python SDK

Private And Secure Data Access — Field-level encryption SDK for Python applications.

## Overview

PANDA (Private And Secure Data Access) is a cross-language SDK for field-level encryption and masking of sensitive personal data. The Python implementation provides the same features as the PHP, Node.js, and Go versions:

- **AES-256-GCM encryption** with envelope wire format
- **Masking-by-default** decrypted values
- **Blind indexing** for searchable encrypted fields
- **Multiple key providers**: Local (.env), HashiCorp Vault, Infisical
- **CLI tool** for initialization and key management
- **Framework integrations**: Django, Flask, FastAPI

## Installation

```bash
pip install panda-py
```

## Quick Start

### 1. Initialize PANDA

```bash
panda init --token panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2
```

The wizard will guide you through:
- Selecting a key provider (Local, Vault, or Infisical)
- Configuring your provider
- Generating your first encryption key

### 2. Use in Your Code

```python
from panda.crypto import FieldCipher, LocalKeyProvider

# Create cipher with local keys
key_provider = LocalKeyProvider()
cipher = FieldCipher(key_provider)

# Encrypt data
envelope = cipher.encrypt("3201012501990001", kid="nik-key")

# Decrypt (returns masked value by default)
masked = cipher.decrypt(envelope)
print(masked)  # "32************01"

# Decrypt raw (audited operation)
raw = cipher.decrypt_raw(envelope)
print(raw)  # "3201012501990001"
```

## Key Providers

### Local (Environment Variables)

```python
from panda.crypto import LocalKeyProvider

# Keys are read from PANDA_KEY_<KID> environment variables
# PANDA_KEY_NIK_KEY=<base64-encoded-32-byte-key>
key_provider = LocalKeyProvider()
```

### HashiCorp Vault

```python
from panda.crypto import VaultKeyProvider

key_provider = VaultKeyProvider(
    vault_url="http://localhost:8200",
    vault_token="your-token",
    mount_path="secret"
)
```

### Infisical

```python
from panda.crypto import InfisicalKeyProvider

key_provider = InfisicalKeyProvider(
    site_url="https://app.infisical.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    project_id="your-project-id",
    environment="dev"
)
```

## Masking

```python
from panda.masking import Masker

# Default: keep 2 leading, 2 trailing characters
masked = Masker.mask("3201012501990001")
# "32************01"

# Custom masking
masked = Masker.mask(
    "3201012501990001",
    keep_leading=3,
    keep_trailing=1,
    mask_char="*"
)
# "320*************1"
```

## Blind Indexing

```python
from panda.blind_index import BlindIndexer

# Generate blind index for searchable encryption
index = BlindIndexer.generate(
    plaintext="3201012501990001",
    key="blind-index-key",
    normalization="digits"  # or "lowercase", "trim", "raw"
)
```

## Framework Integration

### Django

```python
# settings.py
INSTALLED_APPS = [
    ...
    'panda.integrations.django',
]

PANDA = {
    'KEY_PROVIDER_DRIVER': 'local',
    'DEFAULT_KID': 'default-key',
}

# models.py
from panda.integrations.django.fields import EncryptedField
from django.db import models

class Citizen(models.Model):
    nik = EncryptedField(kid='nik-key')
    name = models.CharField(max_length=200)
```

### Flask

```python
from flask import Flask
from panda.integrations.flask import PandaFlask

app = Flask(__name__)
panda = PandaFlask(app)

@app.route('/encrypt')
def encrypt():
    envelope = panda.cipher.encrypt("sensitive data", kid="my-key")
    return envelope.to_json()
```

### FastAPI

```python
from fastapi import FastAPI
from panda.integrations.fastapi import PandaFastAPI

app = FastAPI()
panda = PandaFastAPI(app)

@app.post("/encrypt")
def encrypt_endpoint(data: str):
    envelope = panda.cipher.encrypt(data, kid="my-key")
    return envelope.to_dict()
```

## CLI Commands

```bash
# Initialize PANDA
panda init --token <your-token>

# Generate a new key
panda generate --kid my-key

# Check status
panda status

# View configuration
panda config

# Remove PANDA from project
panda deinit

# Migrate existing plaintext data
panda migrate table_name column_name

# Rotate encryption key
panda rotate-key --old-kid old-key --new-kid new-key

# Permanently shred a key
panda shred my-key
```

## Envelope Format

Encrypted fields use a standardized JSON envelope:

```json
{
  "v": 1,
  "alg": "aes-256-gcm",
  "kid": "key-identifier",
  "nonce": "<base64 12-byte IV>",
  "ciphertext": "<base64 ciphertext + 16-byte auth tag>"
}
```

## Documentation

- [Full Documentation](docs/)
- [Envelope Format Spec](spec/envelope-format.md)
- [CLI Reference](docs/cli.md)
- [Framework Integrations](docs/integrations.md)

## License

MIT License - See LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: https://github.com/jatimprovcsirt/panda-py/issues
- Documentation: https://panda.jatimprovcsirt.go.id
