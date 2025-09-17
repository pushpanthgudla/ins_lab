import textwrap

def row_transpose_encrypt(pt, key):
    cols = len(key)
    pt = pt.ljust((len(pt)+cols-1)//cols*cols, 'X')   # pad
    rows = textwrap.wrap(pt, cols)
    order = sorted(range(cols), key=lambda i: key[i])
    return ''.join(''.join(r[c] for r in rows) for c in order)

def row_transpose_decrypt(ct, key):
    cols = len(key)
    rows = len(ct)//cols
    order = sorted(range(cols), key=lambda i: key[i])
    chunks, i = {}, 0
    for c in order:
        chunks[c], i = ct[i:i+rows], i+rows
    grid = [''.join(chunks[c][r] for c in range(cols)) for r in range(rows)]
    return ''.join(grid).rstrip('X')

# example
k = [3,1,4,2]
pt = "ATTACKATDAWN"
ct = row_transpose_encrypt(pt, k)
print("Cipher:", ct)
print("Plain :", row_transpose_decrypt(ct, k))
