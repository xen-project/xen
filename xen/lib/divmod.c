#include <xen/byteorder.h>
#include <xen/macros.h>
#include <xen/types.h>

/*
 * A couple of 64 bit operations ported from FreeBSD.
 * The code within the '#if BITS_PER_LONG == 32' block below, and no other
 * code in this file, is distributed under the following licensing terms
 * This is the modified '3-clause' BSD license with the obnoxious
 * advertising clause removed, as permitted by University of California.
 *
 * Copyright (c) 1992, 1993
 * The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Depending on the desired operation, we view a `long long' (aka quad_t) in
 * one or more of the following formats.
 */
union uu {
    int64_t        q;              /* as a (signed) quad */
    uint64_t       uq;             /* as an unsigned quad */
    long           sl[2];          /* as two signed longs */
    unsigned long  ul[2];          /* as two unsigned longs */
};

#ifdef __BIG_ENDIAN
#define _QUAD_HIGHWORD 0
#define _QUAD_LOWWORD 1
#else /* __LITTLE_ENDIAN */
#define _QUAD_HIGHWORD 1
#define _QUAD_LOWWORD 0
#endif

/*
 * Define high and low longwords.
 */
#define H               _QUAD_HIGHWORD
#define L               _QUAD_LOWWORD

/*
 * Total number of bits in a quad_t and in the pieces that make it up.
 * These are used for shifting, and also below for halfword extraction
 * and assembly.
 */
#define CHAR_BIT        8               /* number of bits in a char */
#define QUAD_BITS       (sizeof(int64_t) * CHAR_BIT)
#define LONG_BITS       (sizeof(long) * CHAR_BIT)
#define HALF_BITS       (sizeof(long) * CHAR_BIT / 2)

/*
 * Extract high and low shortwords from longword, and move low shortword of
 * longword to upper half of long, i.e., produce the upper longword of
 * ((quad_t)(x) << (number_of_bits_in_long/2)).  (`x' must actually be
 * unsigned long.)
 *
 * These are used in the multiply code, to split a longword into upper
 * and lower halves, and to reassemble a product as a quad_t, shifted left
 * (sizeof(long)*CHAR_BIT/2).
 */
#define HHALF(x)        ((x) >> HALF_BITS)
#define LHALF(x)        ((x) & ((1 << HALF_BITS) - 1))
#define LHUP(x)         ((x) << HALF_BITS)

/*
 * Multiprecision divide.  This algorithm is from Knuth vol. 2 (2nd ed),
 * section 4.3.1, pp. 257--259.
 */
#define B (1 << HALF_BITS) /* digit base */

/* Combine two `digits' to make a single two-digit number. */
#define COMBINE(a, b) (((unsigned long)(a) << HALF_BITS) | (b))

/* select a type for digits in base B */
typedef unsigned long digit;

/*
 * Shift p[0]..p[len] left `sh' bits, ignoring any bits that
 * `fall out' the left (there never will be any such anyway).
 * We may assume len >= 0.  NOTE THAT THIS WRITES len+1 DIGITS.
 */
static void shl(register digit *p, register int len, register int sh)
{
    register int i;

    for (i = 0; i < len; i++)
        p[i] = LHALF(p[i] << sh) | (p[i + 1] >> (HALF_BITS - sh));
    p[i] = LHALF(p[i] << sh);
}

/*
 * __qdivrem(u, v, rem) returns u/v and, optionally, sets *rem to u%v.
 *
 * We do this in base 2-sup-HALF_BITS, so that all intermediate products
 * fit within unsigned long.  As a consequence, the maximum length dividend
 * and divisor are 4 `digits' in this base (they are shorter if they have
 * leading zeros).
 */
u64 __qdivrem(u64 uq, u64 vq, u64 *arq)
{
    union uu tmp;
    digit *u, *v, *q;
    register digit v1, v2;
    unsigned long qhat, rhat, t;
    int m, n, d, j, i;
    digit uspace[5], vspace[5], qspace[5];

    /*
     * Take care of special cases: divide by zero, and u < v.
     */
    if (vq == 0) {
        /* divide by zero. */
        static volatile const unsigned int zero = 0;

        tmp.ul[H] = tmp.ul[L] = 1 / zero;
        if (arq)
            *arq = uq;
        return (tmp.q);
    }
    if (uq < vq) {
        if (arq)
            *arq = uq;
        return (0);
    }
    u = &uspace[0];
    v = &vspace[0];
    q = &qspace[0];

    /*
     * Break dividend and divisor into digits in base B, then
     * count leading zeros to determine m and n.  When done, we
     * will have:
     * u = (u[1]u[2]...u[m+n]) sub B
     * v = (v[1]v[2]...v[n]) sub B
     * v[1] != 0
     * 1 < n <= 4 (if n = 1, we use a different division algorithm)
     * m >= 0 (otherwise u < v, which we already checked)
     * m + n = 4
     * and thus
     * m = 4 - n <= 2
     */
    tmp.uq = uq;
    u[0] = 0;
    u[1] = HHALF(tmp.ul[H]);
    u[2] = LHALF(tmp.ul[H]);
    u[3] = HHALF(tmp.ul[L]);
    u[4] = LHALF(tmp.ul[L]);
    tmp.uq = vq;
    v[1] = HHALF(tmp.ul[H]);
    v[2] = LHALF(tmp.ul[H]);
    v[3] = HHALF(tmp.ul[L]);
    v[4] = LHALF(tmp.ul[L]);
    for (n = 4; v[1] == 0; v++) {
        if (--n == 1) {
            unsigned long rbj; /* r*B+u[j] (not root boy jim) */
            digit q1, q2, q3, q4;

            /*
             * Change of plan, per exercise 16.
             * r = 0;
             * for j = 1..4:
             *  q[j] = floor((r*B + u[j]) / v),
             *  r = (r*B + u[j]) % v;
             * We unroll this completely here.
             */
            t = v[2]; /* nonzero, by definition */
            q1 = u[1] / t;
            rbj = COMBINE(u[1] % t, u[2]);
            q2 = rbj / t;
            rbj = COMBINE(rbj % t, u[3]);
            q3 = rbj / t;
            rbj = COMBINE(rbj % t, u[4]);
            q4 = rbj / t;
            if (arq)
                *arq = rbj % t;
            tmp.ul[H] = COMBINE(q1, q2);
            tmp.ul[L] = COMBINE(q3, q4);
            return (tmp.q);
        }
    }

    /*
     * By adjusting q once we determine m, we can guarantee that
     * there is a complete four-digit quotient at &qspace[1] when
     * we finally stop.
     */
    for (m = 4 - n; u[1] == 0; u++)
        m--;
    for (i = 4 - m; --i >= 0;)
        q[i] = 0;
    q += 4 - m;

    /*
     * Here we run Program D, translated from MIX to C and acquiring
     * a few minor changes.
     *
     * D1: choose multiplier 1 << d to ensure v[1] >= B/2.
     */
    d = 0;
    for (t = v[1]; t < B / 2; t <<= 1)
        d++;
    if (d > 0) {
        shl(&u[0], m + n, d);  /* u <<= d */
        shl(&v[1], n - 1, d);  /* v <<= d */
    }
    /*
     * D2: j = 0.
     */
    j = 0;
    v1 = v[1]; /* for D3 -- note that v[1..n] are constant */
    v2 = v[2]; /* for D3 */
    do {
        register digit uj0, uj1, uj2;

        /*
         * D3: Calculate qhat (\^q, in TeX notation).
         * Let qhat = min((u[j]*B + u[j+1])/v[1], B-1), and
         * let rhat = (u[j]*B + u[j+1]) mod v[1].
         * While rhat < B and v[2]*qhat > rhat*B+u[j+2],
         * decrement qhat and increase rhat correspondingly.
         * Note that if rhat >= B, v[2]*qhat < rhat*B.
         */
        uj0 = u[j + 0]; /* for D3 only -- note that u[j+...] change */
        uj1 = u[j + 1]; /* for D3 only */
        uj2 = u[j + 2]; /* for D3 only */
        if (uj0 == v1) {
            qhat = B;
            rhat = uj1;
            goto qhat_too_big;
        } else {
            unsigned long nn = COMBINE(uj0, uj1);

            qhat = nn / v1;
            rhat = nn % v1;
        }
        while (v2 * qhat > COMBINE(rhat, uj2)) {
        qhat_too_big:
            qhat--;
            if ((rhat += v1) >= B)
                break;
        }
        /*
         * D4: Multiply and subtract.
         * The variable `t' holds any borrows across the loop.
         * We split this up so that we do not require v[0] = 0,
         * and to eliminate a final special case.
         */
        for (t = 0, i = n; i > 0; i--) {
            t = u[i + j] - v[i] * qhat - t;
            u[i + j] = LHALF(t);
            t = (B - HHALF(t)) & (B - 1);
        }
        t = u[j] - t;
        u[j] = LHALF(t);
        /*
         * D5: test remainder.
         * There is a borrow if and only if HHALF(t) is nonzero;
         * in that (rare) case, qhat was too large (by exactly 1).
         * Fix it by adding v[1..n] to u[j..j+n].
         */
        if (HHALF(t)) {
            qhat--;
            for (t = 0, i = n; i > 0; i--) { /* D6: add back. */
                t += u[i + j] + v[i];
                u[i + j] = LHALF(t);
                t = HHALF(t);
            }
            u[j] = LHALF(u[j] + t);
        }
        q[j] = qhat;
    } while (++j <= m);  /* D7: loop on j. */

    /*
     * If caller wants the remainder, we have to calculate it as
     * u[m..m+n] >> d (this is at most n digits and thus fits in
     * u[m+1..m+n], but we may need more source digits).
     */
    if (arq) {
        if (d) {
            for (i = m + n; i > m; --i)
                u[i] = (u[i] >> d) |
                    LHALF(u[i - 1] << (HALF_BITS - d));
            u[i] = 0;
        }
        tmp.ul[H] = COMBINE(uspace[1], uspace[2]);
        tmp.ul[L] = COMBINE(uspace[3], uspace[4]);
        *arq = tmp.q;
    }

    tmp.ul[H] = COMBINE(qspace[1], qspace[2]);
    tmp.ul[L] = COMBINE(qspace[3], qspace[4]);
    return (tmp.q);
}

/*
 * Divide two signed quads.
 * Truncates towards zero, as required by C99.
 */
int64_t __divdi3(int64_t a, int64_t b)
{
    u64 ua, ub, uq;
    int neg = (a < 0) ^ (b < 0);
    ua = (a < 0) ? -(u64)a : a;
    ub = (b < 0) ? -(u64)b : b;
    uq = __qdivrem(ua, ub, (u64 *)0);
    return (neg ? -uq : uq);
}


/*
 * Divide two unsigned quads.
 */
u64 __udivdi3(u64 a, u64 b)
{
    return __qdivrem(a, b, (u64 *)0);
}

/*
 * Remainder of unsigned quad division
 */
u64 __umoddi3(u64 a, u64 b)
{
    u64 rem;
    __qdivrem(a, b, &rem);
    return rem;
}

/*
 * Remainder of signed quad division.
 * Truncates towards zero, as required by C99:
 *  11 %  5 =  1
 * -11 %  5 = -1
 *  11 % -5 =  1
 * -11 % -5 = -1
 */
int64_t __moddi3(int64_t a, int64_t b)
{
    u64 ua, ub, urem;
    int neg = (a < 0);
    ua = neg ? -(u64)a : a;
    ub = (b < 0) ? -(u64)b : b;
    __qdivrem(ua, ub, &urem);
    return (neg ? -urem : urem);
}

/*
 * Quotient and remainder of unsigned long long division
 */
int64_t __ldivmod_helper(int64_t a, int64_t b, int64_t *r)
{
    u64 ua, ub, rem, quot;

    ua = ABS(a);
    ub = ABS(b);
    quot = __qdivrem(ua, ub, &rem);
    if ( a < 0 )
        *r = -rem;
    else
        *r = rem;
    if ( (a < 0) ^ (b < 0) )
        return -quot;
    else
        return quot;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
