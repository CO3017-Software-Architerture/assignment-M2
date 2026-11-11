
## 4. Function Map

### Module: crypto (shared)

| Function | Does | Calls | Called by |
| --- | --- | --- | --- |
| `crypto_init()` | Initializes libsodium | `sodium_init` | main() |
| `sign(sk, msg)` | Detaches Ed25519 signature | `crypto_sign_detached` | `generate_qr()` |
| `verify(pk, sig, msg)` | Verifies a signature | `crypto_sign_verify_detached` | `handle_scan()` |
| `derive_key_id(pk)` | First 8 bytes of SHA-256(pk) | `crypto_hash_sha256` | `load_secret_key()`, `load_key_file()` |
| `random_nonce()` | 8 random bytes | `randombytes_buf` | `generate_qr()` |

### Module: qr\_payload (shared)

| Function | Does | Calls | Called by |
| --- | --- | --- | --- |
| `build_payload(key_id, ts, nonce)` | Packs the 21-byte payload | none | `generate_qr()` |
| `build_signed_message(payload)` | Prepends the domain prefix | none | `generate_qr()`, `handle_scan()` |
| `encode_qr_text(bytes)` | Bytes to Base64url string (no padding) | `sodium_bin2base64` | `generate_qr()` |
| `decode_qr_text(str)` | String back to bytes, or failure, rejecting non-alphabets | `sodium_base642bin` | `handle_scan()` |
| `parse_qr(bytes)` | Checks length and version, splits into payload fields and signature | none | `handle_scan()` |

### Module: generator (stands in for the phone app)

| Function | Does | Calls | Called by |
| --- | --- | --- | --- |
| `load_secret_key(path)` | Reads the 32-byte seed, derives the public key and key\_id | `crypto_sign_seed_keypair`, `derive_key_id()` | main() |
| `generate_qr(secret_key, key_id)` | Builds and signs one QR string | `unix_time()`, `random_nonce()`, `build_payload()`, `build_signed_message()`, `sign()`, `encode_qr_text()` | `qr_refresh_loop()`, tests |
| `qr_refresh_loop()` | Calls `generate_qr()` every 20 s and prints or displays the result | `generate_qr()` | main() |
| `unix_time()` | Current Unix seconds (read as 64-bit, truncated to `uint32_t`) | none | `generate_qr()` |

### Module: key\_cache and nonce\_cache (verifier state)

| Function | Does | Calls | Called by |
| --- | --- | --- | --- |
| `load_key_file(path)` | Parses the keys file, computes each key\_id from its public key, builds the cache | `derive_key_id()` | main() |
| `KeyCache::find(key_id)` | Returns the key record or none | none | `handle_scan()` |
| `NonceCache::seen_or_insert(key_id, nonce, ts)` | Returns true if already present, otherwise stores it | none | `handle_scan()` |
| `NonceCache::purge_expired(now)` | Deletes entries older than 60 s | none | purge timer, or start of `handle_scan()` |

### Module: passback\_state (verifier state, new)
| Function | Does | Calls | Called by |
| --- | --- | --- | --- |
| `check_anti_passback(key_id, direction)` | Reads the key's state. Returns false for ENTRY while the state is IN, or for EXIT while it is OUT. Changes nothing | none | `handle_scan()` |
| `commit_passback(key_id, direction)` | Stores the new state (ENTRY gives IN, EXIT gives OUT) | none | `handle_scan()` |
| `reset_passback(key_id)` | Clears one key's state by hand (back to none), used by security after a PASSBACK denial | none | admin, tests |

### Module: verifier

| Function | Does | Calls | Called by |
| --- | --- | --- | --- |
| `handle_scan(qr_text, direction, now)` | Runs the validation pipeline in section 3C and returns a Decision. Takes `now` as a parameter so tests can fix the time | `NonceCache::purge_expired()`, `decode_qr_text()`, `parse_qr()`, `KeyCache::find()`, `build_signed_message()`, `verify()`, `check_timestamp()`, `NonceCache::seen_or_insert()`, `check_anti_passback()`, `commit_passback()`, `log_event()`, `open_gate()` | scanner input loop, tests |
| `check_timestamp(ts, now)` | True if within the 30 s past, 5 s future window. **Uses `delta = (int32_t)((uint32_t)now - ts)` and accepts `-5 <= delta <= 30`** | none | `handle_scan()` |
| `log_event(decision, key_id, direction, now)` | Appends an audit record, including denials | none | `handle_scan()` |
| `open_gate()` | Simulated relay output (print or GPIO) | none | `handle_scan()` |

## 5. Call Graph

```
STARTUP   main()
            -> crypto_init()
            -> load_secret_key() -> derive_key_id()
            -> load_key_file()   -> derive_key_id()

GENERATE  qr_refresh_loop() -> generate_qr()
            -> unix_time()
            -> random_nonce()
            -> build_payload() -> build_signed_message() -> sign()
            -> encode_qr_text()

VERIFY    handle_scan()
            -> NonceCache::purge_expired()
            -> decode_qr_text() -> parse_qr()
            -> KeyCache::find()
            -> build_signed_message() -> verify()
            -> check_timestamp()
            -> NonceCache::seen_or_insert()
            -> check_anti_passback()
            -> commit_passback()
            -> log_event() -> open_gate()

TEST      harness: generate_qr() -> handle_scan()   (in-process, no network, no camera)
```

## 6. Security Rules to Hold in the Code

- Verify the signature over the exact received bytes. Never re-serialize before verifying.
- Signature check comes first, and the nonce is stored only after it passes.
- Keep the domain prefix on both sides, and never transmit PII in the payload.
- Crypto primitives come from libsodium. Do not write your own.
- Wipe secrets with `sodium_memzero` when finished with them.
- Deny by default: any parse error, missing key, or exception results in DENY plus a log entry.
- Pass `now` into `handle_scan()` instead of reading the clock inside it, so tests can fix the time. In real use the clock must be NTP-synced.
- Log denials as well as allows, and never log the private key or full QR contents.
- Compare timestamps with a signed difference computed in 32-bit arithmetic, never `now - ts` on unsigned values.
- Change anti-passback state only after an ALLOW.

## 7. Known POC Limitations

- Keys are plain files on disk. Anyone who can read the seed file can generate valid codes, and a copied seed works on any device.
- There is no enrollment, attestation, or secure hardware, so nothing proves a key belongs to a genuine device.
- No biometric or user gate sits in front of QR generation.
- Permission changes take effect only when the keys file is reloaded.
- The nonce cache lives in one verifier's memory, so a second verifier would accept the same code inside the window unless the code is bound to a zone.
- A relayed or photographed live QR is valid until its window closes.
- Key changes, including revocation by removing a key, take effect only when the keys file is reloaded. A removed key is logged as UNKNOWN\_KEY.
- The nonce cache lives in one verifier's memory, so a second verifier holding the same key would accept the same code inside the window unless verifiers share nonce state. A restart also clears the cache.
- A relayed or photographed live QR is valid until its window closes.
- The generator's clock is trusted: a user who sets the phone clock ahead can pre-generate codes for future times. Challenge-response or server-issued time would be needed to prevent it.
- Anti-passback state is in memory, so a restart clears it, and it works only if both readers of an area share it.

## 8. Test cases to cover:

| Case | Expected |
| --- | --- |
| Valid fresh code | ALLOW |
| One flipped bit in payload or signature | BAD\_SIGNATURE |
| Timestamp 60 s old, or 60 s in the future | EXPIRED or FUTURE |
| Same code scanned twice | second scan REPLAY |
| Unknown key\_id | UNKNOWN\_KEY |
| Second entry without an exit, or second exit without an entry | PASSBACK |
| Truncated or wrong-version input | MALFORMED |