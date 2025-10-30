import random
import hashlib
from sympy import mod_inverse, isprime

# ---------- Generate Parameters ----------
def generate_params():
    # For simplicity, we use small demo values.
    # In real DSS, p and q are large primes where q divides (p-1)
    p = 23
    q = 11
    if not (isprime(p) and isprime(q) and (p - 1) % q == 0):
        raise ValueError("Invalid parameters! q must divide p-1.")
    g = 2
    return p, q, g

# ---------- Generate Keys ----------
def generate_keys(p, q, g):
    x = random.randint(1, q - 1)  # private key
    y = pow(g, x, p)              # public key
    return x, y

# ---------- Sign Message ----------
def sign_message(msg, p, q, g, x):
    H = int(hashlib.sha1(msg.encode()).hexdigest(), 16) % q
    k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    k_inv = mod_inverse(k, q)  # using sympy for modular inverse
    s = (k_inv * (H + x * r)) % q
    return r, s

# ---------- Verify Signature ----------
def verify_signature(msg, r, s, p, q, g, y):
    H = int(hashlib.sha1(msg.encode()).hexdigest(), 16) % q
    w = mod_inverse(s, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# ---------- MAIN ----------
p, q, g = generate_params()
x, y = generate_keys(p, q, g)

print(f"Public parameters: p={p}, q={q}, g={g}")
print(f"Private key: {x}")
print(f"Public key: {y}")

message = "DSS simplified demo"
r, s = sign_message(message, p, q, g, x)
print(f"\nSignature: r={r}, s={s}")

if verify_signature(message, r, s, p, q, g, y):
    print("\n✅ Signature verified successfully!")
else:
    print("\n❌ Signature verification failed!")
