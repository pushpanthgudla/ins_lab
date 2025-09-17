import textwrap

def columnar_encrypt(pt, key):
    cols = len(key)
    pt = pt.ljust((len(pt)+cols-1)//cols*cols, 'X')
    rows = textwrap.wrap(pt, cols)
    order = sorted(range(cols), key=lambda i: key[i])
    return ''.join(''.join(r[c] for r in rows) for c in order)

def columnar_decrypt(ct, key):
    cols, rows = len(key), len(ct)//len(key)
    order = sorted(range(cols), key=lambda i: key[i])
    chunks, i = {}, 0
    for c in order:
        chunks[c], i = ct[i:i+rows], i+rows
    return ''.join(''.join(chunks[c][r] for c in range(cols)) for r in range(rows)).rstrip('X')

# example
key = [2,0,3,1]
pt = "ATTACKATDAWN"
ct = columnar_encrypt(pt, key)
print("Cipher:", ct)
print("Plain :", columnar_decrypt(ct, key))
