#define INT_SIZE 4

#include "simd.h"
ENTRY(sha_test);

#define SHA(op, a...) __builtin_ia32_sha ## op(a)

#ifdef __AVX512F__
# define ALL_TRUE (~0ULL >> (64 - ELEM_COUNT))
# define eq(x, y) (B(pcmpeqd, _mask, x, y, -1) == ALL_TRUE)
# define blend(x, y, sel) B(movdqa32_, _mask, y, x, sel)
# define rot_c(f, r, x, n) B(pro ## f ## d, _mask, x, n, undef(), ~0)
# define rot_s(f, r, x, n) ({ /* gcc does not support embedded broadcast */ \
    vec_t r_; \
    asm ( "vpro" #f "vd %2%{1to%c3%}, %1, %0" \
          : "=v" (r_) \
          : "v" (x), "m" (n), "i" (ELEM_COUNT) ); \
    r_; \
})
# define rot_v(d, x, n) B(pro ## d ## vd, _mask, x, n, undef(), ~0)
# define shift_s(d, x, n) ({ \
    vec_t r_; \
    asm ( "vps" #d "lvd %2%{1to%c3%}, %1, %0" \
          : "=v" (r_) \
          : "v" (x), "m" (n), "i" (ELEM_COUNT) ); \
    r_; \
})
# define vshift(d, x, n) ({ /* gcc does not allow memory operands */ \
    vec_t r_; \
    asm ( "vps" #d "ldq %2, %1, %0" \
          : "=v" (r_) : "m" (x), "i" ((n) * ELEM_SIZE) ); \
    r_; \
})
#else
# define to_bool(cmp) (__builtin_ia32_pmovmskb128(cmp) == 0xffff)
# define eq(x, y) to_bool((x) == (y))
# define blend(x, y, sel) \
    ((vec_t)__builtin_ia32_pblendw128((vhi_t)(x), (vhi_t)(y), \
                                      ((sel) & 1 ? 0x03 : 0) | \
                                      ((sel) & 2 ? 0x0c : 0) | \
                                      ((sel) & 4 ? 0x30 : 0) | \
                                      ((sel) & 8 ? 0xc0 : 0)))
# define rot_c(f, r, x, n) (sh ## f ## _c(x, n) | sh ## r ## _c(x, 32 - (n)))
# define rot_s(f, r, x, n) ({ /* gcc does not allow memory operands */ \
    vec_t r_, t_, n_ = (vec_t){ 32 } - (n); \
    asm ( "ps" #f "ld %2, %0; ps" #r "ld %3, %1; por %1, %0" \
          : "=&x" (r_), "=&x" (t_) \
          : "m" (n), "m" (n_), "0" (x), "1" (x) ); \
    r_; \
})
static inline unsigned int rotl(unsigned int x, unsigned int n)
{
    return (x << (n & 0x1f)) | (x >> ((32 - n) & 0x1f));
}
static inline unsigned int rotr(unsigned int x, unsigned int n)
{
    return (x >> (n & 0x1f)) | (x << ((32 - n) & 0x1f));
}
# define rot_v(d, x, n) ({ \
    vec_t t_; \
    unsigned int i_; \
    for ( i_ = 0; i_ < ELEM_COUNT; ++i_ ) \
        t_[i_] = rot ## d((x)[i_], (n)[i_]); \
    t_; \
})
# define shift_s(d, x, n) ({ \
    vec_t r_; \
    asm ( "ps" #d "ld %1, %0" : "=&x" (r_) : "m" (n), "0" (x) ); \
    r_; \
})
# define vshift(d, x, n) \
    (vec_t)(__builtin_ia32_ps ## d ## ldqi128((vdi_t)(x), (n) * ELEM_SIZE * 8))
#endif

#define alignr(x, y, n) ((vec_t)__builtin_ia32_palignr128((vdi_t)(x), (vdi_t)(y), (n) * 8))
#define hadd(x, y) __builtin_ia32_phaddd128(x, y)
#define rol_c(x, n) rot_c(l, r, x, n)
#define rol_s(x, n) rot_s(l, r, x, n)
#define rol_v(x, n...) rot_v(l, x, n)
#define ror_c(x, n) rot_c(r, l, x, n)
#define ror_s(x, n) rot_s(r, l, x, n)
#define ror_v(x, n...) rot_v(r, x, n)
#define shl_c(x, n) __builtin_ia32_pslldi128(x, n)
#define shl_s(x, n) shift_s(l, x, n)
#define shr_c(x, n) __builtin_ia32_psrldi128(x, n)
#define shr_s(x, n) shift_s(r, x, n)
#define shuf(x, s) __builtin_ia32_pshufd(x, s)
#define swap(x) shuf(x, 0b00011011)
#define vshl(x, n) vshift(l, x, n)
#define vshr(x, n) vshift(r, x, n)

static inline vec_t sha256_sigma0(vec_t w)
{
    vec_t res;

    touch(w);
    res = ror_c(w, 7);
    touch(w);
    res ^= rol_c(w, 14);
    touch(w);
    res ^= shr_c(w, 3);
    touch(w);

    return res;
}

static inline vec_t sha256_sigma1(vec_t w)
{
    vec_t _17 = { 17 }, _19 = { 19 }, _10 = { 10 };

    return ror_s(w, _17) ^ ror_s(w, _19) ^ shr_s(w, _10);
}

static inline vec_t sha256_Sigma0(vec_t w)
{
    vec_t res, n1 = { 0, 0, 2, 2 }, n2 = { 0, 0, 13, 13 }, n3 = { 0, 0, 10, 10 };

    touch(n1);
    res = ror_v(w, n1);
    touch(n2);
    res ^= ror_v(w, n2);
    touch(n3);

    return res ^ rol_v(w, n3);
}

static inline vec_t sha256_Sigma1(vec_t w)
{
    return ror_c(w, 6) ^ ror_c(w, 11) ^ rol_c(w, 7);
}

int sha_test(void)
{
    unsigned int i;
    vec_t src, one = { 1 };
    vqi_t raw = {};

    for ( i = 1; i < VEC_SIZE; ++i )
        raw[i] = i;
    src = (vec_t)raw;

    for ( i = 0; i < 256; i += VEC_SIZE )
    {
        vec_t x, y, tmp, hash = -src;
        vec_t a, b, c, d, e, g, h;
        unsigned int k, r;

        touch(src);
        x = SHA(1msg1, hash, src);
        touch(src);
        y = hash ^ alignr(hash, src, 8);
        touch(src);

        if ( !eq(x, y) ) return __LINE__;

        touch(src);
        x = SHA(1msg2, hash, src);
        touch(src);
        tmp = hash ^ alignr(src, hash, 12);
        touch(tmp);
        y = rol_c(tmp, 1);
        tmp = hash ^ alignr(src, y, 12);
        touch(tmp);
        y = rol_c(tmp, 1);

        if ( !eq(x, y) ) return __LINE__;

        touch(src);
        x = SHA(1msg2, hash, src);
        touch(src);
        tmp = rol_s(hash ^ alignr(src, hash, 12), one);
        y = rol_s(hash ^ alignr(src, tmp, 12), one);

        if ( !eq(x, y) ) return __LINE__;

        touch(src);
        x = SHA(1nexte, hash, src);
        touch(src);
        touch(hash);
        tmp = rol_c(hash, 30);
        tmp[2] = tmp[1] = tmp[0] = 0;

        if ( !eq(x, src + tmp) ) return __LINE__;

        /*
         * SHA1RNDS4
         *
         * SRC1 = { A0, B0, C0, D0 }
         * SRC2 = W' = { W[0]E0, W[1], W[2], W[3] }
         *
         * (NB that the notation is not C-like, i.e. elements are listed
         * high-to-low everywhere in this comment.)
         *
         * In order to pick a simple rounds function, an immediate value of
         * 1 is used; 3 would also be a possibility.
         *
         * Applying
         *
         * A1 = ROL5(A0) + (B0 ^ C0 ^ D0) + W'[0] + K
         * E1 = D0
         * D1 = C0
         * C1 = ROL30(B0)
         * B1 = A0
         *
         * iteratively four times and resolving round variable values to
         * A<n> and B0, C0, and D0 we get
         *
         * A4 = ROL5(A3) + (A2 ^ ROL30(A1) ^ ROL30(A0)) + W'[3] + ROL30(B0) + K
         * A3 = ROL5(A2) + (A1 ^ ROL30(A0) ^ ROL30(B0)) + W'[2] +       C0  + K
         * A2 = ROL5(A1) + (A0 ^ ROL30(B0) ^       C0 ) + W'[1] +       D0  + K
         * A1 = ROL5(A0) + (B0 ^       C0  ^       D0 ) + W'[0]             + K
         *
         * (respective per-column variable names:
         *  y         a      b          c           d      src           e    k
         * )
         *
         * with
         *
         * B4 = A3
         * C4 = ROL30(A2)
         * D4 = ROL30(A1)
         * E4 = ROL30(A0)
         *
         * and hence
         *
         * DST = { A4, A3, ROL30(A2), ROL30(A1) }
         */

        touch(src);
        x = SHA(1rnds4, hash, src, 1);
        touch(src);

        a = vshr(hash, 3);
        b = vshr(hash, 2);
        touch(hash);
        d = rol_c(hash, 30);
        touch(hash);
        d = blend(d, hash, 0b0011);
        c = vshr(d, 1);
        e = vshl(d, 1);
        tmp = (vec_t){};
        k = rol_c(SHA(1rnds4, tmp, tmp, 1), 2)[0];

        for ( r = 0; r < 4; ++r )
        {
            y = rol_c(a, 5) + (b ^ c ^ d) + swap(src) + e + k;

            switch ( r )
            {
            case 0:
                c[3] = rol_c(y, 30)[0];
                /* fall through */
            case 1:
                b[r + 2] = y[r];
                /* fall through */
            case 2:
                a[r + 1] = y[r];
                break;
            }

            switch ( r )
            {
            case 3:
                if ( a[3] != y[2] ) return __LINE__;
                /* fall through */
            case 2:
                if ( a[2] != y[1] ) return __LINE__;
                if ( b[3] != y[1] ) return __LINE__;
                /* fall through */
            case 1:
                if ( a[1] != y[0] ) return __LINE__;
                if ( b[2] != y[0] ) return __LINE__;
                if ( c[3] != rol_c(y, 30)[0] ) return __LINE__;
                break;
            }
        }

        a = blend(rol_c(y, 30), y, 0b1100);

        if ( !eq(x, a) ) return __LINE__;

        touch(src);
        x = SHA(256msg1, hash, src);
        touch(src);
        y = hash + sha256_sigma0(alignr(src, hash, 4));

        if ( !eq(x, y) ) return __LINE__;

        touch(src);
        x = SHA(256msg2, hash, src);
        touch(src);
        tmp = hash + sha256_sigma1(alignr(hash, src, 8));
        y = hash + sha256_sigma1(alignr(tmp, src, 8));

        if ( !eq(x, y) ) return __LINE__;

        /*
         * SHA256RNDS2
         *
         * SRC1 = { C0, D0, G0, H0 }
         * SRC2 = { A0, B0, E0, F0 }
         * XMM0 = W' = { ?, ?, WK1, WK0 }
         *
         * (NB that the notation again is not C-like, i.e. elements are listed
         * high-to-low everywhere in this comment.)
         *
         * Ch(E,F,G) = (E & F) ^ (~E & G)
         * Maj(A,B,C) = (A & B) ^ (A & C) ^ (B & C)
         *
         * Σ0(A) = ROR2(A) ^ ROR13(A) ^ ROR22(A)
         * Σ1(E) = ROR6(E) ^ ROR11(E) ^ ROR25(E)
         *
         * Applying
         *
         * A1 = Ch(E0, F0, G0) + Σ1(E0) + WK0 + H0 + Maj(A0, B0, C0) + Σ0(A0)
         * B1 = A0
         * C1 = B0
         * D1 = C0
         * E1 = Ch(E0, F0, G0) + Σ1(E0) + WK0 + H0 + D0
         * F1 = E0
         * G1 = F0
         * H1 = G0
         *
         * iteratively four times and resolving round variable values to
         * A<n> / E<n> and B0, C0, D0, F0, G0, and H0 we get
         *
         * A2 = Ch(E1, E0, F0) + Σ1(E1) + WK1 + G0 + Maj(A1, A0, B0) + Σ0(A1)
         * A1 = Ch(E0, F0, G0) + Σ1(E0) + WK0 + H0 + Maj(A0, B0, C0) + Σ0(A0)
         * E2 = Ch(E1, E0, F0) + Σ1(E1) + WK1 + G0 + C0
         * E1 = Ch(E0, F0, G0) + Σ1(E0) + WK0 + H0 + D0
         *
         * with
         *
         * B2 = A1
         * F2 = E1
         *
         * and hence
         *
         * DST = { A2, A1, E2, E1 }
         *
         * which we can simplify a little, by letting A0, B0, and E0 be zero
         * and F0 = ~G0, and by then utilizing
         *
         * Ch(0, 0, x) = x
         * Ch(x, 0, y) = ~x & y
         * Maj(x, 0, 0) = Maj(0, x, 0) = Maj(0, 0, x) = 0
         *
         * A2 = (~E1 & F0) + Σ1(E1) + WK1 + G0 + Σ0(A1)
         * A1 = (~E0 & G0) + Σ1(E0) + WK0 + H0 + Σ0(A0)
         * E2 = (~E1 & F0) + Σ1(E1) + WK1 + G0 + C0
         * E1 = (~E0 & G0) + Σ1(E0) + WK0 + H0 + D0
         *
         * (respective per-column variable names:
         *  y      e    g        e    src    h    d
         * )
         */

        tmp = (vec_t){ ~hash[1] };
        touch(tmp);
        x = SHA(256rnds2, hash, tmp, src);
        touch(tmp);

        e = y = (vec_t){};
        d = alignr(y, hash, 8);
        g = (vec_t){ hash[1], tmp[0], hash[1], tmp[0] };
        h = shuf(hash, 0b01000100);

        for ( r = 0; r < 2; ++r )
        {
            y = (~e & g) + sha256_Sigma1(e) + shuf(src, 0b01000100) +
                h + sha256_Sigma0(d);

            if ( !r )
            {
                d[3] = y[2];
                e[3] = e[1] = y[0];
            }
            else if ( d[3] != y[2] )
                return __LINE__;
            else if ( e[1] != y[0] )
                return __LINE__;
            else if ( e[3] != y[0] )
                return __LINE__;
        }

        if ( !eq(x, y) ) return __LINE__;

        src += 0x01010101 * VEC_SIZE;
    }

    return 0;
}
