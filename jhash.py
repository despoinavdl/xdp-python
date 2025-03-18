import struct

JHASH_INITVAL = 0xdeadbeef

def rol32(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def jhash_mix(a, b, c):
    a = (a - c) & 0xFFFFFFFF; a ^= rol32(c, 4); c = (c + b) & 0xFFFFFFFF
    b = (b - a) & 0xFFFFFFFF; b ^= rol32(a, 6); a = (a + c) & 0xFFFFFFFF
    c = (c - b) & 0xFFFFFFFF; c ^= rol32(b, 8); b = (b + a) & 0xFFFFFFFF
    a = (a - c) & 0xFFFFFFFF; a ^= rol32(c, 16); c = (c + b) & 0xFFFFFFFF
    b = (b - a) & 0xFFFFFFFF; b ^= rol32(a, 19); a = (a + c) & 0xFFFFFFFF
    c = (c - b) & 0xFFFFFFFF; c ^= rol32(b, 4); b = (b + a) & 0xFFFFFFFF
    return a, b, c

def jhash_final(a, b, c):
    c ^= b; c = (c - rol32(b, 14)) & 0xFFFFFFFF
    a ^= c; a = (a - rol32(c, 11)) & 0xFFFFFFFF
    b ^= a; b = (b - rol32(a, 25)) & 0xFFFFFFFF
    c ^= b; c = (c - rol32(b, 16)) & 0xFFFFFFFF
    a ^= c; a = (a - rol32(c, 4)) & 0xFFFFFFFF
    b ^= a; b = (b - rol32(a, 14)) & 0xFFFFFFFF
    c ^= b; c = (c - rol32(b, 24)) & 0xFFFFFFFF
    return a, b, c

def jhash(key, initval=0):
    length = len(key)
    a = b = c = (JHASH_INITVAL + length + initval) & 0xFFFFFFFF

    i = 0
    while length > 12:
        a = (a + struct.unpack_from("<I", key, i)[0]) & 0xFFFFFFFF
        b = (b + struct.unpack_from("<I", key, i+4)[0]) & 0xFFFFFFFF
        c = (c + struct.unpack_from("<I", key, i+8)[0]) & 0xFFFFFFFF
        a, b, c = jhash_mix(a, b, c)
        length -= 12
        i += 12

    last_block = key[i:] + b'\x00' * (12 - len(key[i:]))
    a += struct.unpack_from("<I", last_block, 0)[0]
    b += struct.unpack_from("<I", last_block, 4)[0]
    c += struct.unpack_from("<I", last_block, 8)[0]
    a, b, c = jhash_final(a, b, c)

    return c

# Example usage
# key = b"Hello, JHASH!"
# seed = 12
# print(f"JHASH('{key.decode()}', seed={seed}) = 0x{jhash(key, seed):x}")
