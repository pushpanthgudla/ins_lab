from sympy import mod_inverse, gcd

def generate_keys(p=7919, q=1009):
    n, phi = p*q, (p-1)*(q-1)
    e = next(i for i in range(2, phi) if gcd(i, phi) == 1)
    d = mod_inverse(e, phi)
    return e, d, n

def encrypt(m, e, n): return pow(m, e, n)
def decrypt(c, d, n): return pow(c, d, n)

if __name__ == "__main__":
    e, d, n = generate_keys()
    print(f"Public: ({e}, {n})\nPrivate: ({d}, {n})")
    M = 123
    C = encrypt(M, e, n)
    print("Message:", M, "\nEncrypted:", C, "\nDecrypted:", decrypt(C, d, n))
