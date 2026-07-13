#include "sha256.h"
#include "crypto_util.h"
#include <string.h>

#define ROR(x, n) (((x) >> (n)) | ((x) << (32U - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ROR((x), 2) ^ ROR((x), 13) ^ ROR((x), 22))
#define S1(x) (ROR((x), 6) ^ ROR((x), 11) ^ ROR((x), 25))
#define G0(x) (ROR((x), 7) ^ ROR((x), 18) ^ ((x) >> 3))
#define G1(x) (ROR((x), 17) ^ ROR((x), 19) ^ ((x) >> 10))
#define ROUND(a, b, c, d, e, f, g, h, wk) \
    do                                      \
    {                                       \
        t1 = (h) + S1(e) + CH(e, f, g) + (wk); \
        t2 = S0(a) + MAJ(a, b, c);          \
        (d) += t1;                          \
        (h) = t1 + t2;                      \
    } while (0)
#define SCHED(w, i) \
    ((w)[(i) & 15U] += G1((w)[((i) - 2U) & 15U]) + (w)[((i) - 7U) & 15U] + \
                      G0((w)[((i) - 15U) & 15U]))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

static uint32_t load32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) |
           p[3];
}

static void store32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t) (x >> 24);
    p[1] = (uint8_t) (x >> 16);
    p[2] = (uint8_t) (x >> 8);
    p[3] = (uint8_t) x;
}

static void transform(sha256_context_t *c, const uint8_t *p)
{
    uint32_t w[16];
    uint32_t a;
    uint32_t b;
    uint32_t cc;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t t1;
    uint32_t t2;
    uint32_t i;

    for (i = 0; i < 16; i++)
    {
        w[i] = load32(p + 4 * i);
    }

    a  = c->state[0];
    b  = c->state[1];
    cc = c->state[2];
    d  = c->state[3];
    e  = c->state[4];
    f  = c->state[5];
    g  = c->state[6];
    h  = c->state[7];

    ROUND(a, b, cc, d, e, f, g, h, k[0] + w[0]);
    ROUND(h, a, b, cc, d, e, f, g, k[1] + w[1]);
    ROUND(g, h, a, b, cc, d, e, f, k[2] + w[2]);
    ROUND(f, g, h, a, b, cc, d, e, k[3] + w[3]);
    ROUND(e, f, g, h, a, b, cc, d, k[4] + w[4]);
    ROUND(d, e, f, g, h, a, b, cc, k[5] + w[5]);
    ROUND(cc, d, e, f, g, h, a, b, k[6] + w[6]);
    ROUND(b, cc, d, e, f, g, h, a, k[7] + w[7]);
    ROUND(a, b, cc, d, e, f, g, h, k[8] + w[8]);
    ROUND(h, a, b, cc, d, e, f, g, k[9] + w[9]);
    ROUND(g, h, a, b, cc, d, e, f, k[10] + w[10]);
    ROUND(f, g, h, a, b, cc, d, e, k[11] + w[11]);
    ROUND(e, f, g, h, a, b, cc, d, k[12] + w[12]);
    ROUND(d, e, f, g, h, a, b, cc, k[13] + w[13]);
    ROUND(cc, d, e, f, g, h, a, b, k[14] + w[14]);
    ROUND(b, cc, d, e, f, g, h, a, k[15] + w[15]);
    ROUND(a, b, cc, d, e, f, g, h, k[16] + SCHED(w, 16));
    ROUND(h, a, b, cc, d, e, f, g, k[17] + SCHED(w, 17));
    ROUND(g, h, a, b, cc, d, e, f, k[18] + SCHED(w, 18));
    ROUND(f, g, h, a, b, cc, d, e, k[19] + SCHED(w, 19));
    ROUND(e, f, g, h, a, b, cc, d, k[20] + SCHED(w, 20));
    ROUND(d, e, f, g, h, a, b, cc, k[21] + SCHED(w, 21));
    ROUND(cc, d, e, f, g, h, a, b, k[22] + SCHED(w, 22));
    ROUND(b, cc, d, e, f, g, h, a, k[23] + SCHED(w, 23));
    ROUND(a, b, cc, d, e, f, g, h, k[24] + SCHED(w, 24));
    ROUND(h, a, b, cc, d, e, f, g, k[25] + SCHED(w, 25));
    ROUND(g, h, a, b, cc, d, e, f, k[26] + SCHED(w, 26));
    ROUND(f, g, h, a, b, cc, d, e, k[27] + SCHED(w, 27));
    ROUND(e, f, g, h, a, b, cc, d, k[28] + SCHED(w, 28));
    ROUND(d, e, f, g, h, a, b, cc, k[29] + SCHED(w, 29));
    ROUND(cc, d, e, f, g, h, a, b, k[30] + SCHED(w, 30));
    ROUND(b, cc, d, e, f, g, h, a, k[31] + SCHED(w, 31));
    ROUND(a, b, cc, d, e, f, g, h, k[32] + SCHED(w, 32));
    ROUND(h, a, b, cc, d, e, f, g, k[33] + SCHED(w, 33));
    ROUND(g, h, a, b, cc, d, e, f, k[34] + SCHED(w, 34));
    ROUND(f, g, h, a, b, cc, d, e, k[35] + SCHED(w, 35));
    ROUND(e, f, g, h, a, b, cc, d, k[36] + SCHED(w, 36));
    ROUND(d, e, f, g, h, a, b, cc, k[37] + SCHED(w, 37));
    ROUND(cc, d, e, f, g, h, a, b, k[38] + SCHED(w, 38));
    ROUND(b, cc, d, e, f, g, h, a, k[39] + SCHED(w, 39));
    ROUND(a, b, cc, d, e, f, g, h, k[40] + SCHED(w, 40));
    ROUND(h, a, b, cc, d, e, f, g, k[41] + SCHED(w, 41));
    ROUND(g, h, a, b, cc, d, e, f, k[42] + SCHED(w, 42));
    ROUND(f, g, h, a, b, cc, d, e, k[43] + SCHED(w, 43));
    ROUND(e, f, g, h, a, b, cc, d, k[44] + SCHED(w, 44));
    ROUND(d, e, f, g, h, a, b, cc, k[45] + SCHED(w, 45));
    ROUND(cc, d, e, f, g, h, a, b, k[46] + SCHED(w, 46));
    ROUND(b, cc, d, e, f, g, h, a, k[47] + SCHED(w, 47));
    ROUND(a, b, cc, d, e, f, g, h, k[48] + SCHED(w, 48));
    ROUND(h, a, b, cc, d, e, f, g, k[49] + SCHED(w, 49));
    ROUND(g, h, a, b, cc, d, e, f, k[50] + SCHED(w, 50));
    ROUND(f, g, h, a, b, cc, d, e, k[51] + SCHED(w, 51));
    ROUND(e, f, g, h, a, b, cc, d, k[52] + SCHED(w, 52));
    ROUND(d, e, f, g, h, a, b, cc, k[53] + SCHED(w, 53));
    ROUND(cc, d, e, f, g, h, a, b, k[54] + SCHED(w, 54));
    ROUND(b, cc, d, e, f, g, h, a, k[55] + SCHED(w, 55));
    ROUND(a, b, cc, d, e, f, g, h, k[56] + SCHED(w, 56));
    ROUND(h, a, b, cc, d, e, f, g, k[57] + SCHED(w, 57));
    ROUND(g, h, a, b, cc, d, e, f, k[58] + SCHED(w, 58));
    ROUND(f, g, h, a, b, cc, d, e, k[59] + SCHED(w, 59));
    ROUND(e, f, g, h, a, b, cc, d, k[60] + SCHED(w, 60));
    ROUND(d, e, f, g, h, a, b, cc, k[61] + SCHED(w, 61));
    ROUND(cc, d, e, f, g, h, a, b, k[62] + SCHED(w, 62));
    ROUND(b, cc, d, e, f, g, h, a, k[63] + SCHED(w, 63));

    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += cc;
    c->state[3] += d;
    c->state[4] += e;
    c->state[5] += f;
    c->state[6] += g;
    c->state[7] += h;
}

void sha256_init(sha256_context_t *c)
{
    static const uint32_t initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    if (!c)
    {
        return;
    }

    memcpy(c->state, initial, sizeof initial);
    c->total_size  = 0;
    c->buffer_size = 0;
}

void sha256_update(sha256_context_t *c, const void *data, size_t size)
{
    const uint8_t *p = (const uint8_t *) data;
    size_t         n;

    if (!c || c->buffer_size >= SHA256_BLOCK_SIZE || (!p && size))
    {
        return;
    }

    c->total_size += size;

    if (c->buffer_size)
    {
        n = SHA256_BLOCK_SIZE - c->buffer_size;
        if (n > size)
        {
            n = size;
        }

        memcpy(c->buffer + c->buffer_size, p, n);
        c->buffer_size += n;
        p += n;
        size -= n;

        if (c->buffer_size == SHA256_BLOCK_SIZE)
        {
            transform(c, c->buffer);
            c->buffer_size = 0;
        }
    }

    while (size >= SHA256_BLOCK_SIZE)
    {
        transform(c, p);
        p += SHA256_BLOCK_SIZE;
        size -= SHA256_BLOCK_SIZE;
    }

    if (size)
    {
        memcpy(c->buffer, p, size);
        c->buffer_size = size;
    }
}

void sha256_final(sha256_context_t *c, uint8_t digest[32])
{
    uint64_t bits;
    size_t   i;

    if (!c || !digest || c->buffer_size >= SHA256_BLOCK_SIZE)
    {
        return;
    }

    bits                        = c->total_size * 8U;
    c->buffer[c->buffer_size++] = 0x80;

    if (c->buffer_size > 56)
    {
        memset(c->buffer + c->buffer_size, 0, SHA256_BLOCK_SIZE - c->buffer_size);
        transform(c, c->buffer);
        c->buffer_size = 0;
    }

    memset(c->buffer + c->buffer_size, 0, 56 - c->buffer_size);

    for (i = 0; i < 8; i++)
    {
        c->buffer[63 - i] = (uint8_t) (bits >> (8 * i));
    }

    transform(c, c->buffer);

    for (i = 0; i < 8; i++)
    {
        store32(digest + 4 * i, c->state[i]);
    }

    crypto_secure_zero(c, sizeof *c);
}

void sha256_compute(const void *data, size_t size, uint8_t digest[32])
{
    sha256_context_t c;

    sha256_init(&c);
    sha256_update(&c, data, size);
    sha256_final(&c, digest);
}
