import textwrap

def columnar_encrypt(pt, key):
    cols = len(key)
    # pad to full block
    pt = pt.ljust((len(pt)+cols-1)//cols*cols, 'X')
    grid = textwrap.wrap(pt, cols)
    return ''.join(grid[r][k-1] for k in key for r in range(len(grid)))

def columnar_decrypt(ct, key):
    cols, rows = len(key), len(ct)//len(key)
    grid = [['']*cols for _ in range(rows)]
    idx = 0
    for k in key:
        for r in range(rows):
            grid[r][k-1] = ct[idx]; idx += 1
    return ''.join(''.join(row) for row in grid).rstrip('X')

# example
if __name__ == "__main__":
    pt, key = "ATTACKATDAWN", [3,1,4,2]
    ct = columnar_encrypt(pt, key)
    print(ct)                 # TAWACDATNTKA
    print(columnar_decrypt(ct, key))  # ATTACKATDAWN
