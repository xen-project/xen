/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SHA2-256: https://csrc.nist.gov/pubs/fips/180-2/upd1/final
 *
 * Originally derived from Linux.  Modified substantially to optimise for size
 * and Xen's expected usecases.
 */
#include <xen/bitops.h>
#include <xen/sha2.h>
#include <xen/string.h>
#include <xen/unaligned.h>

struct sha2_256_state {
    uint32_t state[SHA2_256_DIGEST_SIZE / sizeof(uint32_t)];
    uint8_t buf[64];
    size_t count; /* Byte count. */
};

static uint32_t choose(uint32_t x, uint32_t y, uint32_t z)
{
    return z ^ (x & (y ^ z));
}

static uint32_t majority(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (z & (x | y));
}

static uint32_t e0(uint32_t x)
{
    return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22);
}

static uint32_t e1(uint32_t x)
{
    return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25);
}

static uint32_t s0(uint32_t x)
{
    return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3);
}

static uint32_t s1(uint32_t x)
{
    return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10);
}

static uint32_t blend(uint32_t W[16], unsigned int i)
{
#define W(i) W[(i) & 15]

    return W(i) += s1(W(i - 2)) + W(i - 7) + s0(W(i - 15));

#undef W
}

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha2_256_transform(uint32_t *state, const void *_input)
{
    const uint32_t *input = _input;
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t W[16];
    unsigned int i;

    for ( i = 0; i < 16; i++ )
        W[i] = get_unaligned_be32(&input[i]);

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for ( i = 0; i < 16; i += 8 )
    {
        t1 = h + e1(e) + choose(e, f, g) + K[i + 0] + W[i + 0];
        t2 = e0(a) + majority(a, b, c);    d += t1;    h = t1 + t2;
        t1 = g + e1(d) + choose(d, e, f) + K[i + 1] + W[i + 1];
        t2 = e0(h) + majority(h, a, b);    c += t1;    g = t1 + t2;
        t1 = f + e1(c) + choose(c, d, e) + K[i + 2] + W[i + 2];
        t2 = e0(g) + majority(g, h, a);    b += t1;    f = t1 + t2;
        t1 = e + e1(b) + choose(b, c, d) + K[i + 3] + W[i + 3];
        t2 = e0(f) + majority(f, g, h);    a += t1;    e = t1 + t2;
        t1 = d + e1(a) + choose(a, b, c) + K[i + 4] + W[i + 4];
        t2 = e0(e) + majority(e, f, g);    h += t1;    d = t1 + t2;
        t1 = c + e1(h) + choose(h, a, b) + K[i + 5] + W[i + 5];
        t2 = e0(d) + majority(d, e, f);    g += t1;    c = t1 + t2;
        t1 = b + e1(g) + choose(g, h, a) + K[i + 6] + W[i + 6];
        t2 = e0(c) + majority(c, d, e);    f += t1;    b = t1 + t2;
        t1 = a + e1(f) + choose(f, g, h) + K[i + 7] + W[i + 7];
        t2 = e0(b) + majority(b, c, d);    e += t1;    a = t1 + t2;
    }

    for ( ; i < 64; i += 8 )
    {
        t1 = h + e1(e) + choose(e, f, g) + K[i + 0] + blend(W, i + 0);
        t2 = e0(a) + majority(a, b, c);    d += t1;    h = t1 + t2;
        t1 = g + e1(d) + choose(d, e, f) + K[i + 1] + blend(W, i + 1);
        t2 = e0(h) + majority(h, a, b);    c += t1;    g = t1 + t2;
        t1 = f + e1(c) + choose(c, d, e) + K[i + 2] + blend(W, i + 2);
        t2 = e0(g) + majority(g, h, a);    b += t1;    f = t1 + t2;
        t1 = e + e1(b) + choose(b, c, d) + K[i + 3] + blend(W, i + 3);
        t2 = e0(f) + majority(f, g, h);    a += t1;    e = t1 + t2;
        t1 = d + e1(a) + choose(a, b, c) + K[i + 4] + blend(W, i + 4);
        t2 = e0(e) + majority(e, f, g);    h += t1;    d = t1 + t2;
        t1 = c + e1(h) + choose(h, a, b) + K[i + 5] + blend(W, i + 5);
        t2 = e0(d) + majority(d, e, f);    g += t1;    c = t1 + t2;
        t1 = b + e1(g) + choose(g, h, a) + K[i + 6] + blend(W, i + 6);
        t2 = e0(c) + majority(c, d, e);    f += t1;    b = t1 + t2;
        t1 = a + e1(f) + choose(f, g, h) + K[i + 7] + blend(W, i + 7);
        t2 = e0(b) + majority(b, c, d);    e += t1;    a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha2_256_init(struct sha2_256_state *s)
{
    *s = (struct sha2_256_state){
        .state = {
            0x6a09e667UL,
            0xbb67ae85UL,
            0x3c6ef372UL,
            0xa54ff53aUL,
            0x510e527fUL,
            0x9b05688cUL,
            0x1f83d9abUL,
            0x5be0cd19UL,
        },
    };
}

static void sha2_256_update(struct sha2_256_state *s, const void *msg,
                            size_t len)
{
    unsigned int partial = s->count & 63;

    s->count += len;

    if ( (partial + len) >= 64 )
    {
        if ( partial )
        {
            unsigned int rem = 64 - partial;

            /* Fill the partial block. */
            memcpy(s->buf + partial, msg, rem);
            msg += rem;
            len -= rem;

            sha2_256_transform(s->state, s->buf);
            partial = 0;
        }

        for ( ; len >= 64; msg += 64, len -= 64 )
            sha2_256_transform(s->state, msg);
    }

    /* Remaining data becomes partial. */
    memcpy(s->buf + partial, msg, len);
}

static void sha2_256_final(struct sha2_256_state *s, void *_dst)
{
    uint32_t *dst = _dst;
    unsigned int i, partial = s->count & 63;

    /* Start padding */
    s->buf[partial++] = 0x80;

    if ( partial > 56 )
    {
        /* Need one extra block - pad to 64 */
        memset(s->buf + partial, 0, 64 - partial);
        sha2_256_transform(s->state, s->buf);
        partial = 0;
    }
    /* Pad to 56 */
    memset(s->buf + partial, 0, 56 - partial);

    /* Append the bit count */
    put_unaligned_be64((uint64_t)s->count << 3, &s->buf[56]);
    sha2_256_transform(s->state, s->buf);

    /* Store state in digest */
    for ( i = 0; i < 8; i++ )
        put_unaligned_be32(s->state[i], &dst[i]);
}

void sha2_256_digest(uint8_t digest[SHA2_256_DIGEST_SIZE],
                     const void *msg, size_t len)
{
    struct sha2_256_state s;

    sha2_256_init(&s);
    sha2_256_update(&s, msg, len);
    sha2_256_final(&s, digest);
}

#ifdef CONFIG_SELF_TESTS

#include <xen/init.h>
#include <xen/lib.h>

static const struct test {
    const char *msg;
    uint8_t digest[SHA2_256_DIGEST_SIZE];
} tests[] __initconst = {
    {
        .msg = "abc",
        .digest = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        },
    },
    {
        .msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        .digest = {
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
            0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
            0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
            0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
        },
    },
};

static void __init __constructor test_sha2_256(void)
{
    for ( unsigned int i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        uint8_t res[SHA2_256_DIGEST_SIZE] = {};

        sha2_256_digest(res, t->msg, strlen(t->msg));

        if ( memcmp(res, t->digest, sizeof(t->digest)) == 0 )
            continue;

        panic("%s() msg '%s' failed\n"
              "  expected %" STR(SHA2_256_DIGEST_SIZE) "phN\n"
              "       got %" STR(SHA2_256_DIGEST_SIZE) "phN\n",
              __func__, t->msg, t->digest, res);
    }
}
#endif /* CONFIG_SELF_TESTS */
