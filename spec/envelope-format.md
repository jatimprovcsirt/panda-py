# PANDA Envelope Format (v1)

This document describes the canonical wire format for encrypted personal data fields in the PANDA SDK.

## Structure

All encrypted fields are stored as a JSON object (serialized to string) with the following structure:

```json
{
  "v": 1,
  "alg": "aes-256-gcm",
  "kid": "opd-dukcapil-key-1",
  "nonce": "<base64 encoded 12 bytes>",
  "ciphertext": "<base64 encoded (ciphertext + 16-byte authentication tag concatenated)>"
}
```

## Fields

| Field | Type | Description |
|---|---|---|
| `v` | integer | Envelope version. Must be `1` for this specification version. |
| `alg` | string | Cipher algorithm. Must be `"aes-256-gcm"`. |
| `kid` | string | Key identifier, matching `^[a-zA-Z0-9._-]+$`. Max 255 bytes. |
| `nonce` | string | RFC 4648 §4 standard base64 encoded 12-byte initialization vector (IV). |
| `ciphertext` | string | RFC 4648 §4 standard base64 encoded concatenated byte array: `AES-GCM-Ciphertext ‖ 16-byte GCM Tag`. |
