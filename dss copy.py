import random
import hashlib
from sympy import isprime, mod_inverse, nextprime

# --- Generate random parameters ---
def generate_params():
    q = nextprime(random.randint(10, 50))     # small prime q
    while True:
        p = q * random.randint(5, 20) + 1     # ensure p = k*q + 1
        if isprime(p):
            break
    g = pow(2, (p - 1) // q, p)               # simple generator
    return p, q, g

# --- Generate keys ---
def generate_keys(p, q, g):
    x = random.randint(1, q - 1)  # private key
    y = pow(g, x, p)              # public key
    return x, y

# --- Sign a message ---
def sign(msg, p, q, g, x):
    H = int(hashlib.sha1(msg.encode()).hexdigest(), 16) % q
    k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    s = (mod_inverse(k, q) * (H + x * r)) % q
    return r, s

# --- Verify signature ---
def verify(msg, r, s, p, q, g, y):
    H = int(hashlib.sha1(msg.encode()).hexdigest(), 16) % q
    w = mod_inverse(s, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# --- Main program ---
p, q, g = generate_params()
x, y = generate_keys(p, q, g)
msg = "Hello DSS"

print(f"p={p}, q={q}, g={g}")
print(f"Private key={x}, Public key={y}")

r, s = sign(msg, p, q, g, x)
print(f"\nSignature: r={r}, s={s}")

if verify(msg, r, s, p, q, g, y):
    print("\n✅ Signature verified!")
else:
    print("\n❌ Verification failed!")
