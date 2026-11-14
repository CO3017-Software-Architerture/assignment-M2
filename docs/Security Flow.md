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
- A nonce cache is used to prevent replay attacks. Entries are keyed by (key\_id, nonce) and only need to live while the timestamp could still pass the window (35 s), so the 60 s TTL keeps the cache from growing unbounded.
- **This is different from the functional reqs; changing the refresh interval to shorter (than specified 60s-120s) is now feasible.**

| Field | Size | Notes |
| --- | --- | --- |
| version | 1 byte | `0x01` |
| key\_id | 8 bytes | First 8 bytes of SHA-256(public key). No PII (employee ID) used. |
| timestamp | 4 bytes | Unsigned Unix seconds, big-endian |
| nonce | 8 bytes | Random, (practically) unique per QR code |
| signature | 64 bytes | Ed25519 over the prefix followed by the exact 21 payload bytes in table order: version, key_id, timestamp, nonce |

**Notes:**
- Key ID is the first 8 bytes of SHA-256(public key), transmitted in digest order and interpreted as a big-endian integer in C++.
- In practice, the verifier clock is synced to NTP. The timestamp on the QR is assumed to be authentic. In a real production system, the generator clock must be verified to be NTP-synced (App Attestation).
- Timestamp is 4 bytes unsigned big-endian, so it will roll over in 2106.

Total is 85 bytes, encoded to text for the QR image.

The verifier CLI accepts provisioned public keys as hexadecimal arguments and
keeps them in memory. A scan is one line in the form `IN <qr_text>` or
`OUT <qr_text>`. Both directions share one verifier.

## 3. Workflows

### A. Startup: load provisioned data

1. Generator calls `load_secret_key(path)`, which reads the seed, derives the public key, and computes the `key_id`.

2. Verifier calls `load_key_file(path)`, which fills the `KeyCache` with `{key_id, public_key}` per entry. The `key_id` is computed from each public key, never read from the file.

3. Verifier creates an empty `NonceCache` and an empty `PassbackState`.

### B. Client-side QR generation (every 20 s)

1. `now = unix_time()` (read as 64-bit, truncated to uint32_t), `nonce = random_nonce()`.
2. `build_payload(key_id, now, nonce)` produces 21 bytes.
3. `sign(secret_key, build_signed_message(payload))` produces 64 bytes.
4. `encode_qr_text(payload + signature)` produces the string that would be rendered as the QR (114 Base64url characters).

### C. Verification and decision (per scan)

`handle_scan()` runs these checks in order and stops at the first failure. Every outcome is logged. The result is a Decision with allow (true or false) and a reason code. `direction` (ENTRY or EXIT) is set by which reader produced the scan.

| Step | Check | Function | Reject reason |
| --- | --- | --- | --- |
| 1 | Text decodes, length is 85, version is 1 | `decode_qr_text()`, `parse_qr()` | MALFORMED |
| 2 | key\_id exists in local cache | `KeyCache::find()` | UNKNOWN\_KEY |
| 3 | Signature valid over the exact received bytes | `verify()` | BAD\_SIGNATURE |
| 4 | Timestamp within window | `check_timestamp()` | EXPIRED or FUTURE |
| 5 | Nonce not seen before (insert only now) | `NonceCache::seen_or_insert()` | REPLAY |
| 6 | Anti-passback state allows this direction | `check_anti_passback()` | PASSBACK |
| 7 | Log ALLOW, open gate | `log_event()`, `open_gate()` | none |

The nonce is inserted only after steps 1 to 4 pass (valid signature and fresh timestamp), so unauthenticated scans cannot fill the cache.

### D. Anti-passback (new)

Anti-passback stops one key from entering twice, or exiting twice, without the opposite scan in between, for example when the owner enters and then sends a fresh QR to a person waiting outside.

**State per key\_id:** `IN`, `OUT`, or none (the starting state).

| Direction | Current state | Decision | New state |
| --- | --- | --- | --- |
| ENTRY | none or OUT | ALLOW | IN |
| ENTRY | IN | DENY (PASSBACK) | unchanged |
| EXIT | none or IN | ALLOW | OUT |
| EXIT | OUT | DENY (PASSBACK) | unchanged |

A repeated ENTRY or a repeated EXIT is denied. A person denied this way must report to security, who clear the key with `reset_passback(key_id)`.

**How it runs inside `handle_scan()`:**

1. Step 6 is reached only after steps 1 to 5 pass.
2. `check_anti_passback(key_id, direction)` reads the key's state and applies the table above. It changes nothing.
3. If it returns false, the Decision is DENY with reason PASSBACK, the event is logged, and the gate stays closed.
4. Otherwise step 7 calls `commit_passback(key_id, direction)` to store the new state, then logs and opens the gate.

**Rules to hold in the code:**

- State changes only on ALLOW. A scan denied for any reason leaves it untouched.
- The entry-side and exit-side readers of one area must share the same `PassbackState` (one process handles both, or the state is shared). Otherwise EXIT scans never reset the state and the employee cannot re-enter.
- `reset_passback(key_id)` clears one key's state by hand, which security uses to resolve PASSBACK denials.
- State is in memory, so a restart clears it and every key goes back to none and its next ENTRY or EXIT is allowed. Persist it to a file if that matters.
- This is hard mode (deny). A soft mode (allow but log a warning) only changes the result of step 6.
