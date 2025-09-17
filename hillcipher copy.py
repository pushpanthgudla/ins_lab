import numpy as np

def mod_inverse(a, m):
    # Extended Euclidean Algorithm
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inv(matrix, modulus):
    det = int(round(np.linalg.det(matrix)))  # determinant
    det = det % modulus
    det_inv = mod_inverse(det, modulus)
    if det_inv is None:
        raise Exception("Matrix is not invertible under modulo", modulus)

    # adjugate matrix
    inv_matrix = np.array([[matrix[1][1], -matrix[0][1]],
                           [-matrix[1][0], matrix[0][0]]])
    
    return (det_inv * inv_matrix) % modulus

def text_to_numbers(text):
    return [ord(c) - 97 for c in text]

def numbers_to_text(nums):
    return ''.join(chr(int(n) + 97) for n in nums)

def encrypt(message, key):
    message = message.replace(" ", "").lower()
    if len(message) % 2 != 0:
        message += 'x'

    result = []
    for i in range(0, len(message), 2):
        pair = np.array(text_to_numbers(message[i:i+2]))
        enc = key.dot(pair) % 26
        result.extend(enc)
    return numbers_to_text(result)

def decrypt(cipher, key):
    inv_key = matrix_mod_inv(key, 26)
    result = []
    for i in range(0, len(cipher), 2):
        pair = np.array(text_to_numbers(cipher[i:i+2]))
        dec = inv_key.dot(pair) % 26
        result.extend(dec)
    return numbers_to_text(result)

# Example usage
key = np.array([[3, 3],
                [2, 5]])

msg = "hillcipher"
enc = encrypt(msg, key)
dec = decrypt(enc, key)

print("Original:", msg)
print("Encrypted:", enc)
print("Decrypted:", dec)
print("Inverse Key Matrix:\n", matrix_mod_inv(key, 26))
