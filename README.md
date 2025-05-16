# 🔐 Garuda Key Exchange Secure Messaging

**Project 13** under the **Garuda Sentinel** mission.  
This project demonstrates a basic implementation of **secure message exchange** using:

- 🔑 **Diffie-Hellman Key Exchange** for establishing a shared secret between two parties.
- 🔐 **AES Symmetric Encryption** (with the shared secret) for message confidentiality.

---

## 🧠 Concept Overview

### 🎯 Goal:
Enable two parties, **Alice (Sender)** and **Bob (Receiver)**, to securely exchange a message without directly sharing the encryption key.

### 🔁 Workflow:

1. **Key Exchange**:
   - Alice and Bob each generate a **private key** and compute their **public key** using Diffie-Hellman.
   - They exchange public keys (over insecure channels).

2. **Shared Secret Generation**:
   - Both compute the same shared secret independently using their private key and the other's public key.

3. **Encryption**:
   - Alice derives a symmetric key from the shared secret using SHA-256 and encrypts the message using AES.
   - She sends the **ciphertext** and her **public key** to Bob.

4. **Decryption**:
   - Bob derives the same symmetric key using the shared secret logic.
   - He decrypts the ciphertext to recover the original message.

---

## 🚀 Files in This Project

### 📁 `alice_send.py`
- Generates Alice's keys
- Simulates Bob’s public key (for testing)
- Accepts a message input
- Encrypts the message with AES (ECB mode for simplicity)
- Prints:
  - Ciphertext (hex)
  - Alice’s public key

### 📁 `bob_receive.py`
- Generates Bob's private/public key pair
- Accepts:
  - Alice’s public key
  - Encrypted message
- Recalculates the shared secret
- Decrypts and displays the original message

---

## 📦 Requirements

- Python 3.x
- `pycryptodome` library:
  ```bash
  pip install pycryptodome
🛡 Security Notes
This is a learning-level simulation:

AES in ECB mode is not secure for real-world usage.

In production, use AES-GCM or AES-CBC with IV.

For real systems:

Use validated public key cryptography libraries.

Perform identity verification to prevent MITM attacks.

Include MAC or AEAD modes for integrity.

🧭 Future Upgrades
✅ Use AES-GCM for authenticated encryption.

🔄 Implement asymmetric key exchange over network sockets.

🛠 Add digital signatures for message integrity verification.

☁️ Extend for cloud message exchange with secure endpoints.

🔖 Project Metadata
Mission: Garuda Sentinel

Project ID: 13

Title: Key Exchange Secure Messaging

Focus: Diffie-Hellman Key Exchange, Symmetric Encryption

Status: ✅ Completed
