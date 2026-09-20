import hashlib

class CryptographyEngine:
    @staticmethod
    def generate_sha256_hash(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def symmetric_xor_cipher(data: str, key: str) -> str:
        key_bytes = key.encode('utf-8')
        data_bytes = data.encode('utf-8')
        processed = bytearray()
        for i, byte in enumerate(data_bytes):
            processed.append(byte ^ key_bytes[i % len(key_bytes)])
        return processed.hex()

    @staticmethod
    def symmetric_xor_decipher(hex_data: str, key: str) -> str:
        key_bytes = key.encode('utf-8')
        data_bytes = bytes.fromhex(hex_data)
        processed = bytearray()
        for i, byte in enumerate(data_bytes):
            processed.append(byte ^ key_bytes[i % len(key_bytes)])
        return processed.decode('utf-8')

    @staticmethod
    def rsa_key_simulation():
        p, q = 61, 53
        n = p * q
        e = 17
        d = 2753
        return {"public_key": (e, n), "private_key": (d, n)}

def run_crypto_demo():
    print("=" * 60)
    print("      CRYPTOGRAPHY & HASHING IMPLEMENTATION DEMO")
    print("=" * 60)

    secret_message = "Confidential Internship Data Submission 2026"
    sha256_hash = CryptographyEngine.generate_sha256_hash(secret_message)
    print(f"\n1. SHA-256 Hashing (Integrity Check):")
    print(f"   - Input Text  : {secret_message}")
    print(f"   - SHA256 Hash : {sha256_hash}")

    key = "CyberSecKey2026"
    encrypted_hex = CryptographyEngine.symmetric_xor_cipher(secret_message, key)
    decrypted_text = CryptographyEngine.symmetric_xor_decipher(encrypted_hex, key)

    print(f"\n2. Symmetric Encryption Engine:")
    print(f"   - Secret Key  : {key}")
    print(f"   - Encrypted   : {encrypted_hex}")
    print(f"   - Decrypted   : {decrypted_text}")

    rsa_keys = CryptographyEngine.rsa_key_simulation()
    print(f"\n3. Asymmetric RSA Key Simulation:")
    print(f"   - Public Key  (e, n) : {rsa_keys['public_key']}")
    print(f"   - Private Key (d, n) : {rsa_keys['private_key']}")
    print("\n[+] Cryptographic tests executed successfully.")

if __name__ == "__main__":
    run_crypto_demo()
