#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define rol32(x, r) ((x << r) | (x >> (32 - r)))

#define __jhash_mix(a, b, c)  \
{                             \
    a -= c;  a ^= rol32(c, 4);  c += b;  \
    b -= a;  b ^= rol32(a, 6);  a += c;  \
    c -= b;  c ^= rol32(b, 8);  b += a;  \
    a -= c;  a ^= rol32(c, 16); c += b;  \
    b -= a;  b ^= rol32(a, 19); a += c;  \
    c -= b;  c ^= rol32(b, 4);  b += a;  \
}

#define __jhash_final(a, b, c)  \
{                              \
    c ^= b; c -= rol32(b, 14);  \
    a ^= c; a -= rol32(c, 11);  \
    b ^= a; b -= rol32(a, 25);  \
    c ^= b; c -= rol32(b, 16);  \
    a ^= c; a -= rol32(c, 4);   \
    b ^= a; b -= rol32(a, 14);  \
    c ^= b; c -= rol32(b, 24);  \
}

#define JHASH_INITVAL 0xdeadbeef

static inline uint32_t jhash(const void *key, uint32_t length, uint32_t initval) {
    uint32_t a, b, c;
    const uint8_t *k = (const uint8_t *)key;

    a = b = c = JHASH_INITVAL + length + initval;

    while (length > 12) {
        a += *(uint32_t *)(k);
        b += *(uint32_t *)(k + 4);
        c += *(uint32_t *)(k + 8);
        __jhash_mix(a, b, c);
        length -= 12;
        k += 12;
    }

    switch (length) {
        case 12: c += (uint32_t)k[11] << 24; // fall through
        case 11: c += (uint32_t)k[10] << 16; // fall through
        case 10: c += (uint32_t)k[9] << 8;   // fall through
        case 9:  c += k[8];                  // fall through
        case 8:  b += (uint32_t)k[7] << 24;  // fall through
        case 7:  b += (uint32_t)k[6] << 16;  // fall through
        case 6:  b += (uint32_t)k[5] << 8;   // fall through
        case 5:  b += k[4];                  // fall through
        case 4:  a += (uint32_t)k[3] << 24;  // fall through
        case 3:  a += (uint32_t)k[2] << 16;  // fall through
        case 2:  a += (uint32_t)k[1] << 8;   // fall through
        case 1:  a += k[0];
                 __jhash_final(a, b, c);
        case 0: break;
    }

    return c;
}

int main() {
    const char *data = "Hello, JHASH!";
    uint32_t seed = 12;
    uint32_t hash = jhash(data, strlen(data), seed);

    printf("JHASH('%s', seed=%u) = 0x%x\n", data, seed, hash);
    return 0;
}
