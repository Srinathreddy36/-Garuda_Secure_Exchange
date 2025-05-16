import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

# Diffie-Hellman parameters
prime = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
generator = 2

# Alice's private and public key
alice_private_key = secrets.randbelow(prime - 2) + 2
alice_public_key = pow(generator, alice_private_key, prime)

# Simulate Bob’s public key (in real world, this is received)
bob_private_key = secrets.randbelow(prime - 2) + 2
bob_public_key = pow(generator, bob_private_key, prime)

# Shared secret
shared_secret = pow(bob_public_key, alice_private_key, prime)

# Derive AES key from shared secret (SHA-256)
aes_key = hashlib.sha256(str(shared_secret).encode()).digest()

# Message input
message = input("📨 Enter message to send securely: ").strip()
message_bytes = message.encode()

# Encrypt using AES (ECB just for simplicity here)
cipher = AES.new(aes_key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message_bytes, AES.block_size))

print("\n🔐 Encrypted Message (hex):", ciphertext.hex())
print("📤 Send this along with Alice's Public Key to Bob.")
print("🗝️ Alice's Public Key:", alice_public_key)
