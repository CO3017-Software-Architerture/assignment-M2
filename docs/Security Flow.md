# QR Turnstile Verification Module: Security Workflow

This is a workflow and call graph for a QR-based turnstile access control system. It is intended to be implemented in C or C++ using libsodium for cryptography, and a small JSON parser for the keys file.

## 1. Scope and Components

**In scope:** QR generation, QR verification, and the allow or deny decision.

**Assumed already in place:**

- An Ed25519 secret seed in a local file, read by the generator.
- A keys file with a list of unique public keys, read by the verifier.
- As mentioned in the report; each turnstile has its own copy of the keys file (effectively resulting in area-based access control).
- The keys file is provisioned and updated from outside this module (i.e. central server).

**Out of scope:** role-based or temporal-based area access rules, enrollment, attestation, secure hardware, biometric authentication, active re-synchronization, or any other network communication.

| Component | Role | Holds |
| --- | --- | --- |
| QR generator (stands in for the phone app) | Builds, signs, and encodes a fresh QR string every 20 s | Secret seed, its own key\_id |
| Verifier (stands in for the kiosk & turnstile) | Decodes, verifies, and decides ALLOW or DENY | Public key cache, nonce cache, local anti-passback|
| Provisioned files | Fixed inputs created outside this module | Secret seed file, keys file |

Libraries: [libsodium](https://github.com/jedisct1/libsodium) (Ed25519, SHA-256, random bytes, harder to get wrong), a small JSON parser for the keys file (or not, instead injecting right at runtime), any Base64url encoder (we choose base64url encoding already present in libsodium), as well as a QR renderer, using [nayuki's](https://github.com/nayuki/QR-Code-generator)

## 2. Constants and QR Format

| Constant | Value |
| --- | --- |
| Domain prefix (signed, not transmitted) | `corp-qr-access-v1` |
| QR refresh interval | 20s |
| Accepted timestamp window | 30s in the past, 5s into the future |
| Nonce cache TTL | 60 s |

**Notes:**
- Domain prefix is prepended to the payload before signing, but not transmitted in the QR. The verifier must have the same prefix hard-coded. This is for blocking usage in other domains, and for future-proofing if the QR format changes.
- Acceptance window is 30s into the past because of possible clock drift and scan/decode latency.
- **This is different from the functional reqs; changing the refresh interval to shorter (than specified 60s-120s) is now feasible.**

| Field | Size | Notes |
| --- | --- | --- |
| version | 1 byte | `0x01` |
| key\_id | 8 bytes | First 8 bytes of SHA-256(public key). No PII (employee ID) used. |
| timestamp | 4 bytes | Unix seconds, big-endian |
| nonce | 8 bytes | Random, (practically) unique per QR code |
| signature | 64 bytes | Ed25519 over `prefix + key\_id + version + timestamp + nonce` |

**Notes:**
- Key ID is first 8 bytes of SHA-256(public key), resulting in 64 bits of entropy, making collisions extremely unlikely.
- In practice, the verifier clock is synced to NTP.

Total is 85 bytes, encoded to text for the QR image.

## 3. Workflows

### A. Startup: load provisioned data

1. Generator calls `load_secret_key(path)`, which reads the seed, derives the public key, and computes the `key_id`.

2. Verifier calls `load_key_file(path)`, which fills the `KeyCache` with `{key_id, public_key}` per entry. The `key_id` is computed from each public key, never read from the file.

3. Verifier creates an empty `NonceCache`.

### B. Client-side QR generation (every 20 s)

1. `now = unix_time()`, `nonce = random_nonce()`.
2. `build_payload(key_id, now, nonce)` produces 21 bytes.
3. `sign(secret_key, build_signed_message(payload))` produces 64 bytes.
4. `encode_qr_text(payload + signature)` produces the string that would be rendered as the QR.

### C. Verification and decision (per scan)

`handle_scan()` runs these checks in order and stops at the first failure. Every outcome is logged. The result is a Decision with allow (true or false) and a reason code.

| Step | Check | Function | Reject reason |
| --- | --- | --- | --- |
| 1 | Text decodes, length is 85, version is 1 | `decode_qr_text()`, `parse_qr()` | MALFORMED |
| 2 | key\_id exists in local cache | `KeyCache::find()` | UNKNOWN\_KEY |
| 3 | Signature valid over the exact received bytes | `verify()` | BAD\_SIGNATURE |
| 4 | Timestamp within window | `check_timestamp()` | EXPIRED or FUTURE |
| 5 | Nonce not seen before (insert only now) | `NonceCache::seen_or_insert()` | REPLAY |
| 6 | Anti-passback state allows this direction | `check_anti_passback()` | PASSBACK |
| 7 | Log ALLOW, open gate | `log_event()`, `open_gate()` | none |

The nonce is inserted only after the signature is proven valid.
