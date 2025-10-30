import random

# ---------- Step 1: Check for primality ----------
def is_prime(n):
    """Simple check for prime number (not optimized, for learning only)."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


# ---------- Step 2: Find primitive root ----------
def find_primitive_root(p):
    """Find the smallest primitive root modulo p."""
    required_set = {num for num in range(1, p) if gcd(p, num) == 1}
    print(required_set)
    for g in range(2, p):
        actual_set = {pow(g, powers, p) for powers in range(1, p)}
        print(actual_set)
        if required_set == actual_set:
            return g
    return None


# ---------- Step 3: Greatest Common Divisor ----------
def gcd(a, b):
    """Compute GCD (Euclidean Algorithm)."""
    while b:
        a, b = b, a % b
    return a


# ---------- Step 4: Randomly select a prime ----------
def generate_prime(start=100000, end=999999):
    """Generate a random prime between start and end."""
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

# ---------- Step 5: Diffie-Hellman Key Exchange ----------
# Random prime
p = generate_prime()
print("Randomly selected prime (p):", p)

# Find a primitive root modulo p
g = find_primitive_root(p)
if g is None:
    print("No primitive root found (try again)")
else:
    print("Primitive root (g):", g)

# Random private keys for Alice and Bob
a = random.randint(2, p - 2)   # Alice's private key
b = random.randint(2, p - 2)   # Bob's private key
print("\nAlice's private key (a):", a)
print("Bob's private key (b):", b)

# Compute public keys
A = pow(g, a, p)   # Alice's public key
B = pow(g, b, p)   # Bob's public key
print("\nAlice's public key (A):", A)
print("Bob's public key (B):", B)

# Compute shared secret
shared_A = pow(B, a, p)   # Computed by Alice
shared_B = pow(A, b, p)   # Computed by Bob
print("\nShared key computed by Alice:", shared_A)
print("Shared key computed by Bob:", shared_B)

if shared_A == shared_B:
    shared_key = shared_A
    print("\n✅ Shared secret key:", shared_key)
else:
    print("\n❌ Key exchange failed!")
    exit()

# ---------- Step 5: Encrypt a text file ----------
def xor_encrypt_decrypt(data, key):
    """Simple XOR encryption/decryption with integer key."""
    key_byte = key % 256
    return bytes([b ^ key_byte for b in data])

# Create a simple text file
with open("secret.txt", "w") as f:
    f.write("This is a top secret file!")

# Read and encrypt
with open("secret.txt", "rb") as f:
    plaintext = f.read()

encrypted = xor_encrypt_decrypt(plaintext, shared_key)
with open("encrypted.bin", "wb") as f:
    f.write(encrypted)

print("\nFile encrypted successfully as 'encrypted.bin'")

# Decrypt back
with open("encrypted.bin", "rb") as f:
    encrypted_data = f.read()

decrypted = xor_encrypt_decrypt(encrypted_data, shared_key)
with open("decrypted.txt", "wb") as f:
    f.write(decrypted)

print("File decrypted successfully as 'decrypted.txt'")

# Display decrypted content
with open("decrypted.txt", "r") as f:
    print("\nDecrypted file content:", f.read())
