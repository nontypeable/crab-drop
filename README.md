# 🦀 crab-drop

**Simple, fast, and secure file transfer over a local network.**

`crab-drop` is a CLI tool for secure peer-to-peer file transfer between two devices on the same local network.

---

## ✨ Features

- 🔐 **End-to-end encryption** (ChaCha20-Poly1305)
- 🔍 **Automatic device discovery** via mDNS
- 🔑 **Mutual authentication** using a shared secret phrase
- 📦 **Chunked file transfer** with integrity checks
- ⚡ **High-speed local transfers**

---

## 🔐 Security model

`crab-drop` uses a **pre-shared secret phrase** to:

- discover peers on the local network
- perform mutual authentication
- derive a unique session key for each transfer

The secret phrase is **never transmitted over the network in plaintext**.

### Cryptography

- **Key derivation:** HKDF
- **Authenticated encryption:** ChaCha20-Poly1305 (AEAD)
- **Session keys:** ephemeral, unique per transfer
- **Integrity:** per-chunk verification + final file hash

---

## 🧠 Protocol flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (Sender)
    participant S as Server (Receiver)
    participant D as mDNS

    %% =========================
    %% 1. Device Discovery
    %% =========================
    Note over C,S: 1. Device Discovery (mDNS)
    C->>D: mDNS query: service + hash(secret_phrase)
    S->>D: mDNS response: service + hash(secret_phrase)
    Note over C,S: Peers discovered (shared secret confirmed)

    %% =========================
    %% 2. Pre-shared Key Derivation
    %% =========================
    Note over C,S: 2. Pre-shared Key
    Note over C,S: psk = HKDF(secret_phrase, "psk-discovery")

    %% =========================
    %% 3. Secure Handshake
    %% =========================
    Note over C,S: 3. Encrypted Handshake (AEAD)

    C->>S: TCP CONNECT
    Note over C: client_nonce, client_token = random(32)

    C->>S: nonce_c1, AEAD(psk, client_token, AAD=handshake)
    alt Decryption failed
        S->>C: Close connection
    else OK
        Note over S: Verify + extract client_token
        Note over S: server_token = random(32)

        S->>C: nonce_s1, AEAD(psk, client_token, AAD=confirm)
        S->>C: nonce_s2, AEAD(psk, server_token, AAD=server_auth)
    end

    Note over C: Verify echoed client_token
    Note over C,S: session_key = HKDF(client_token || server_token, "session")

    %% =========================
    %% 4. Secure File Transfer
    %% =========================
    Note over C,S: 4. Encrypted File Transfer

    C->>S: nonce_f1, AEAD(session_key, file_header, AAD=meta)
    S-->>C: nonce_f2, AEAD(session_key, "READY", AAD=ack)

    loop File chunks
        C->>S: nonce_n, AEAD(session_key, chunk_data, AAD=chunk_index)
        S-->>C: nonce_m, AEAD(session_key, chunk_hash, AAD=ack)
    end

    Note over S: Verify final file hash
    S->>C: nonce_end, AEAD(session_key, "OK", AAD=final)

    Note over C,S: Secure transfer complete
```

---

## 📜 License

MIT
