import secrets
from hashlib import sha256
from Crypto.Cipher import AES

def diffie_hellman_shared_key(p, g):
    # Generate private keys for Alice and Bob
    alice_private = secrets.randbelow(p - 2) + 2
    bob_private = secrets.randbelow(p - 2) + 2

    # Compute public keys
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)

    # Compute shared secret keys
    alice_shared_secret = pow(bob_public, alice_private, p)
    bob_shared_secret = pow(alice_public, bob_private, p)

    # Derive AES key by hashing shared secret and truncating to 16 bytes (128 bits)
    alice_key = sha256(str(alice_shared_secret).encode()).digest()[:16]
    bob_key = sha256(str(bob_shared_secret).encode()).digest()[:16]

    return alice_key, bob_key

def encrypt_message(key, message):
    nonce = secrets.token_bytes(12)  # 12 bytes nonce for AES-GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return nonce, ciphertext, tag

def decrypt_message(key, nonce, ciphertext, tag):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode(), True
    except Exception:
        return None, False

def main():
    print("🔐 Garuda Secure Communication Using Diffie-Hellman + AES-GCM 🔐\n")

    # Prime and base (public parameters)
    p = 0xFFFFFFFB
    g = 5

    # Generate shared keys for Alice and Bob
    alice_key, bob_key = diffie_hellman_shared_key(p, g)

    # Alice inputs the secret message
    message = input("🔊 Alice: Enter a secret message to encrypt and send to Bob:\n> ")

    # Alice encrypts the message
    nonce, ciphertext, tag = encrypt_message(alice_key, message)

    print("\n📤 Message encrypted and sent to Bob:")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Nonce (hex):      {nonce.hex()}")
    print(f"Tag (hex):        {tag.hex()}\n")

    # Bob decrypts and verifies the message
    decrypted_message, verified = decrypt_message(bob_key, nonce, ciphertext, tag)

    print("📩 Bob received and decrypted the message:")
    if verified:
        print(f"✅ Decrypted Message: {decrypted_message}")
        print("✅ Integrity Verified: Message is authentic.")
    else:
        print("❌ Integrity Check Failed! Message may have been tampered.")

if __name__ == "__main__":
    main()
