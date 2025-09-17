import numpy as np
from sympy import Matrix

def text_to_nums(text):
    return [ord(c) - 97 for c in text.lower() if c.isalpha()]

def nums_to_text(nums):
    return ''.join(chr(n % 26 + 97) for n in nums)

def hill_encrypt(msg, key):
    n = key.shape[0]
    nums = text_to_nums(msg)
    if len(nums) % n != 0:
        nums += [23] * (n - len(nums) % n)   # pad with 'x'
    result = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        enc = key.dot(block) % 26
        result.extend(enc)
    return nums_to_text(result)

def hill_decrypt(cipher, key):
    n = key.shape[0]
    inv_key = np.array(Matrix(key).inv_mod(26)).astype(int)
    nums = text_to_nums(cipher)
    result = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        dec = inv_key.dot(block) % 26
        result.extend(dec)
    return nums_to_text(result)

# Example usage
key2 = np.array([[3, 3],
                 [2, 5]])

key3 = np.array([[6, 24, 1],
                 [13, 16, 10],
                 [20, 17, 15]])

msg = "hillcipher"
print("2x2 enc:", hill_encrypt(msg, key2))
print("2x2 dec:", hill_decrypt(hill_encrypt(msg, key2), key2))
print("3x3 enc:", hill_encrypt(msg, key3))
print("3x3 dec:", hill_decrypt(hill_encrypt(msg, key3), key3))
print("Inverse Key 2x2:\n", np.array(Matrix(key2).inv_mod(26)).astype(int))
print("Inverse Key 3x3:\n", np.array(Matrix(key3).inv_mod(26)).astype(int))