def rail_fence_encrypt(text, rails):
    if rails <= 1: return text
    fence, rail, dirn = ['']*rails, 0, 1
    for ch in text:
        fence[rail] += ch
        rail += dirn
        if rail in (0, rails-1): dirn *= -1
    return ''.join(fence)

def rail_fence_decrypt(cipher, rails):
    if rails <= 1: return cipher
    n, rail, dirn, pattern = len(cipher), 0, 1, []
    for _ in range(n):
        pattern.append(rail)
        rail += dirn
        if rail in (0, rails-1): dirn *= -1
    counts = [pattern.count(r) for r in range(rails)]
    parts, i = [], 0
    for c in counts: parts.append(list(cipher[i:i+c])); i += c
    return ''.join(parts[r].pop(0) for r in pattern)

# example
ct = rail_fence_encrypt("WEAREDISCOVEREDFLEEATONCE", 3)
print("Cipher:", ct)
print("Plain :", rail_fence_decrypt(ct, 3))
