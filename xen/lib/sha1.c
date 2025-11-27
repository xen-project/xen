/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SHA1: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
 *
 * Originally derived from Linux.  Modified substantially to optimise for size
 * and Xen's expected usecases.
 */
#include <xen/bitops.h>
#include <xen/sha1.h>
#include <xen/string.h>
#include <xen/unaligned.h>

struct sha1_state {
    size_t count; /* Byte Count. */
    uint32_t state[SHA1_DIGEST_SIZE / sizeof(uint32_t)];
    uint8_t buf[64];
};

static uint32_t blend(uint32_t w[16], unsigned int i)
{
#define W(i) w[(i) & 15]

    return W(i) = rol32(W(i + 13) ^ W(i + 8) ^ W(i + 2) ^ W(i), 1);

#undef W
}

static void sha1_transform(uint32_t state[5], const void *_input)
{
    const uint32_t *input = _input;
    uint32_t a, b, c, d, e, t;
    uint32_t w[16];
    unsigned int i = 0;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* Round 1 - iterations 0-16 take their input from 'input' */
    for ( ; i < 16; ++i )
    {
        t = get_unaligned_be32(&input[i]);
        w[i] = t;
        e += t + rol32(a, 5) + (((c ^ d) & b) ^ d) + 0x5a827999U;
        b = ror32(b, 2);
        t = e; e = d; d = c; c = b; b = a; a = t;
    }

    /* Round 1 tail. Input from 512-bit mixing array */
    for ( ; i < 20; ++i )
    {
        t = blend(w, i);
        e += t + rol32(a, 5) + (((c ^ d) & b) ^ d) + 0x5a827999U;
        b = ror32(b, 2);
        t = e; e = d; d = c; c = b; b = a; a = t;
    }

    /* Round 2 */
    for ( ; i < 40; ++i )
    {
        t = blend(w, i);
        e += t + rol32(a, 5) + (b ^ c ^ d) + 0x6ed9eba1U;
        b = ror32(b, 2);
        t = e; e = d; d = c; c = b; b = a; a = t;
    }

    /* Round 3 */
    for ( ; i < 60; ++i )
    {
        t = blend(w, i);
        e += t + rol32(a, 5) + ((b & c) + (d & (b ^ c))) + 0x8f1bbcdcU;
        b = ror32(b, 2);
        t = e; e = d; d = c; c = b; b = a; a = t;
    }

    /* Round 4 */
    for ( ; i < 80; ++i )
    {
        t = blend(w, i);
        e += t + rol32(a, 5) + (b ^ c ^ d) + 0xca62c1d6U;
        b = ror32(b, 2);
        t = e; e = d; d = c; c = b; b = a; a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void sha1_init(struct sha1_state *s)
{
    *s = (struct sha1_state){
        .state = {
            0x67452301U,
            0xefcdab89U,
            0x98badcfeU,
            0x10325476U,
            0xc3d2e1f0U,
        },
    };
}

static void sha1_update(struct sha1_state *s, const void *msg, size_t len)
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

            sha1_transform(s->state, s->buf);
            partial = 0;
        }

        for ( ; len >= 64; msg += 64, len -= 64 )
            sha1_transform(s->state, msg);
    }

    /* Remaining data becomes partial. */
    memcpy(s->buf + partial, msg, len);
}

static void sha1_final(struct sha1_state *s, uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint32_t *dst = (uint32_t *)digest;
    unsigned int i, partial = s->count & 63;

    /* Start padding */
    s->buf[partial++] = 0x80;

    if ( partial > 56 )
    {
        /* Need one extra block - pad to 64 */
        memset(s->buf + partial, 0, 64 - partial);
        sha1_transform(s->state, s->buf);
        partial = 0;
    }
    /* Pad to 56 */
    memset(s->buf + partial, 0x0, 56 - partial);

    /* Append the bit count */
    put_unaligned_be64((uint64_t)s->count << 3, &s->buf[56]);
    sha1_transform(s->state, s->buf);

    /* Store state in digest */
    for ( i = 0; i < 5; i++ )
        put_unaligned_be32(s->state[i], &dst[i]);
}

void sha1(uint8_t digest[SHA1_DIGEST_SIZE], const void *msg, size_t len)
{
    struct sha1_state s;

    sha1_init(&s);
    sha1_update(&s, msg, len);
    sha1_final(&s, digest);
}

#ifdef CONFIG_SELF_TESTS

#include <xen/init.h>
#include <xen/lib.h>

static const struct test {
    const char *msg;
    uint8_t digest[SHA1_DIGEST_SIZE];
} tests[] __initconst = {
    {
        .msg = "abc",
        .digest = {
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
            0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        },
    },
    {
        .msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        .digest = {
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
            0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        },
    },
};

static void __init __constructor test_sha1(void)
{
    for ( unsigned int i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        uint8_t res[SHA1_DIGEST_SIZE] = {};

        sha1(res, t->msg, strlen(t->msg));

        if ( memcmp(res, t->digest, sizeof(t->digest)) == 0 )
            continue;

        panic("%s() msg '%s' failed\n"
              "  expected %" STR(SHA1_DIGEST_SIZE) "phN\n"
              "       got %" STR(SHA1_DIGEST_SIZE) "phN\n",
              __func__, t->msg, t->digest, res);
    }
}
#endif /* CONFIG_SELF_TESTS */
