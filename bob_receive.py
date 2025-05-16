import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import secrets

# Diffie-Hellman parameters
prime = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
generator = 2

# Bob's private and public key
bob_private_key = secrets.randbelow(prime - 2) + 2
bob_public_key = pow(generator, bob_private_key, prime)

print("🗝️ Bob's Public Key:", bob_public_key)
print("📌 Bob's Private Key (keep this secret):", bob_private_key)

# Input from Alice
alice_public_key = int(input("\n🔐 Enter Alice's Public Key: ").strip())
ciphertext_hex = input("📥 Enter Encrypted Message (hex): ").strip()
ciphertext = bytes.fromhex(ciphertext_hex)

# Shared secret
shared_secret = pow(alice_public_key, bob_private_key, prime)

# Derive AES key from shared secret
aes_key = hashlib.sha256(str(shared_secret).encode()).digest()

# Decrypt
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("\n✅ Decrypted Message:", decrypted.decode())
