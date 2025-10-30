import sys

# --- SHA-256 Constants ---
# (First 32 bits of the fractional parts of the square roots of the first 8 primes)
H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# (First 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# --- Bitwise Operations ---
# All operations are modulo 2^32

def rotr(x, n):
    """Circular right shift (rotate) on a 32-bit integer."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def shr(x, n):
    """Logical right shift."""
    return (x >> n) & 0xFFFFFFFF

# SHA-256 logical functions
def Ch(x, y, z):
    """Choose: (x AND y) XOR (NOT x AND z)"""
    return ((x & y) ^ (~x & z)) & 0xFFFFFFFF

def Maj(x, y, z):
    """Majority: (x AND y) XOR (x AND z) XOR (y AND z)"""
    return ((x & y) ^ (x & z) ^ (y & z)) & 0xFFFFFFFF

def Sigma0(x):
    """ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)"""
    return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) & 0xFFFFFFFF

def Sigma1(x):
    """ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)"""
    return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) & 0xFFFFFFFF

def sigma0(x):
    """ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)"""
    return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)) & 0xFFFFFFFF

def sigma1(x):
    """ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)"""
    return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)) & 0xFFFFFFFF


def sha256(message_bytes):
    """
    Computes the SHA-256 hash of a byte string.
    """
    
    # --- 1. Pre-processing and Padding ---
    
    # Get the original message length in bits
    mlen_bits = len(message_bytes) * 8
    
    # Append the '1' bit (0x80 byte)
    padded_message = message_bytes + b'\x80'
    
    # Append '0' bits (0x00 bytes) until length is 56 (mod 64)
    # 512 bits = 64 bytes. We need space for the 8-byte length field.
    # (len % 64) == 56
    while len(padded_message) % 64 != 56:
        padded_message += b'\x00'
        
    # Append the original length (as a 64-bit big-endian integer)
    padded_message += mlen_bits.to_bytes(8, 'big')

    # --- 2. Process the message in 512-bit (64-byte) chunks ---
    
    # Initialize hash values (make a copy of the constants)
    h = list(H)
    
    # Split the padded message into 64-byte chunks
    chunks = [padded_message[i:i+64] for i in range(0, len(padded_message), 64)]
    
    for chunk in chunks:
        # --- 3. Create the message schedule (W[0...63]) ---
        W = [0] * 64
        
        # First 16 words (W[0]-W[15]) are from the chunk
        for t in range(16):
            W[t] = int.from_bytes(chunk[t*4:t*4+4], 'big')
            
        # Extend to 64 words (W[16]-W[63])
        for t in range(16, 64):
            W[t] = (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]) & 0xFFFFFFFF

        # --- 4. Initialize working variables ---
        a, b, c, d, e, f, g, h_prime = h
        
        # --- 5. Compression Loop (64 rounds) ---
        for t in range(64):
            # T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
            T1 = (h_prime + Sigma1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
            
            # T2 = Sigma0(a) + Maj(a,b,c)
            T2 = (Sigma0(a) + Maj(a, b, c)) & 0xFFFFFFFF
            
            # "Shuffle" the registers
            h_prime = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF
            
        # --- 6. Compute intermediate hash values ---
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + h_prime) & 0xFFFFFFFF
        
    # --- 7. Final Hash ---
    # Concatenate the final hash values (H0 to H7)
    final_hash_bytes = b''.join(x.to_bytes(4, 'big') for x in h)
    
    return final_hash_bytes.hex()

# --- Example Usage ---
if __name__ == "__main__":
    # Get input from command line arguments or use a default
    if len(sys.argv) > 1:
        input_string = " ".join(sys.argv[1:])
    else:
        input_string = "hello"

    # The input must be encoded as bytes
    input_bytes = input_string.encode('utf-8')
    
    hash_hex = sha256(input_bytes)
    
    print(f"Input:    '{input_string}'")
    print(f"SHA-256:  {hash_hex}")

    # You can verify this result using a standard tool:
    # On Linux/macOS: echo -n "hello" | sha256sum
    # On Windows (PowerShell): [System.Text.Encoding]::UTF8.GetBytes("hello") | Get-FileHash -Algorithm SHA256
    #
    # Known hashes for comparison:
    # "hello" -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    # "" (empty string) -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    # "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad