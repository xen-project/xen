/*
 *  lzo.c -- LZO1X Compressor from LZO
 *
 *  Copyright (C) 1996-2012 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Adapted for Xen (files combined and syntactic/header changes) by:
 *  Dan Magenheimer <dan.magenheimer@oracle.com>
 *
 */

/*
 *  lzodefs.h -- architecture, OS and compiler specific defines
 *
 *  Copyright (C) 1996-2012 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for Linux kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */


#define COPY4(dst, src)    \
        put_unaligned(get_unaligned((const u32 *)(src)), (u32 *)(dst))
#if defined(__x86_64__)
#define COPY8(dst, src)    \
        put_unaligned(get_unaligned((const u64 *)(src)), (u64 *)(dst))
#else
#define COPY8(dst, src)    \
        COPY4(dst, src); COPY4((dst) + 4, (src) + 4)
#endif

#ifdef __MINIOS__
# include <lib.h>
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  undef __BIG_ENDIAN
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
#  undef __LITTLE_ENDIAN
# endif
#endif

#if defined(__BIG_ENDIAN) && defined(__LITTLE_ENDIAN)
#error "conflicting endian definitions"
#elif defined(__x86_64__)
#define LZO_USE_CTZ64    1
#define LZO_USE_CTZ32    1
#elif defined(__i386__) || defined(__powerpc__)
#define LZO_USE_CTZ32    1
#elif defined(__arm__) && (__LINUX_ARM_ARCH__ >= 5)
#define LZO_USE_CTZ32    1
#endif

#define M1_MAX_OFFSET 0x0400
#define M2_MAX_OFFSET 0x0800
#define M3_MAX_OFFSET 0x4000
#define M4_MAX_OFFSET 0xbfff

#define M1_MIN_LEN 2
#define M1_MAX_LEN 2
#define M2_MIN_LEN 3
#define M2_MAX_LEN 8
#define M3_MIN_LEN 3
#define M3_MAX_LEN 33
#define M4_MIN_LEN 3
#define M4_MAX_LEN 9

#define M1_MARKER 0
#define M2_MARKER 64
#define M3_MARKER 32
#define M4_MARKER 16

#define lzo_dict_t unsigned short
#define D_BITS  13
#define D_SIZE  (1u << D_BITS)
#define D_MASK  (D_SIZE - 1)
#define D_HIGH  ((D_MASK >> 1) + 1)

/*
 *  LZO1X Compressor from LZO
 *
 *  Copyright (C) 1996-2012 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for Linux kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */

#ifdef __XEN__
#include <xen/lib.h>
#include <asm/byteorder.h>
#endif

#include <xen/lzo.h>
#define get_unaligned(_p) (*(_p))
#define put_unaligned(_val,_p) (*(_p)=_val)
#define get_unaligned_le16(_p) (*(u16 *)(_p))
#define get_unaligned_le32(_p) (*(u32 *)(_p))

static noinline size_t
lzo1x_1_do_compress(const unsigned char *in, size_t in_len,
                    unsigned char *out, size_t *out_len,
                    size_t ti, void *wrkmem)
{
    const unsigned char *ip;
    unsigned char *op;
    const unsigned char * const in_end = in + in_len;
    const unsigned char * const ip_end = in + in_len - 20;
    const unsigned char *ii;
    lzo_dict_t * const dict = (lzo_dict_t *) wrkmem;

    op = out;
    ip = in;
    ii = ip;
    ip += ti < 4 ? 4 - ti : 0;

    for (;;) {
        const unsigned char *m_pos;
        size_t t, m_len, m_off;
        u32 dv;
    literal:
        ip += 1 + ((ip - ii) >> 5);
    next:
        if (unlikely(ip >= ip_end))
            break;
        dv = get_unaligned_le32(ip);
        t = ((dv * 0x1824429d) >> (32 - D_BITS)) & D_MASK;
        m_pos = in + dict[t];
        dict[t] = (lzo_dict_t) (ip - in);
        if (unlikely(dv != get_unaligned_le32(m_pos)))
            goto literal;

        ii -= ti;
        ti = 0;
        t = ip - ii;
        if (t != 0) {
            if (t <= 3) {
                op[-2] |= t;
                COPY4(op, ii);
                op += t;
            } else if (t <= 16) {
                *op++ = (t - 3);
                COPY8(op, ii);
                COPY8(op + 8, ii + 8);
                op += t;
            } else {
                if (t <= 18) {
                    *op++ = (t - 3);
                } else {
                    size_t tt = t - 18;
                    *op++ = 0;
                    while (unlikely(tt > 255)) {
                        tt -= 255;
                        *op++ = 0;
                    }
                    *op++ = tt;
                }
                do {
                    COPY8(op, ii);
                    COPY8(op + 8, ii + 8);
                    op += 16;
                    ii += 16;
                    t -= 16;
                } while (t >= 16);
                if (t > 0) do {
                    *op++ = *ii++;
                } while (--t > 0);
            }
        }

        m_len = 4;
        {
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && defined(LZO_USE_CTZ64)
        u64 v;
        v = get_unaligned((const u64 *) (ip + m_len)) ^
            get_unaligned((const u64 *) (m_pos + m_len));
        if (unlikely(v == 0)) {
            do {
                m_len += 8;
                v = get_unaligned((const u64 *) (ip + m_len)) ^
                    get_unaligned((const u64 *) (m_pos + m_len));
                if (unlikely(ip + m_len >= ip_end))
                    goto m_len_done;
            } while (v == 0);
        }
#  if defined(__LITTLE_ENDIAN)
        m_len += (unsigned) __builtin_ctzll(v) / 8;
#  elif defined(__BIG_ENDIAN)
        m_len += (unsigned) __builtin_clzll(v) / 8;
#  else
#    error "missing endian definition"
#  endif
#elif defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && defined(LZO_USE_CTZ32)
        u32 v;
        v = get_unaligned((const u32 *) (ip + m_len)) ^
            get_unaligned((const u32 *) (m_pos + m_len));
        if (unlikely(v == 0)) {
            do {
                m_len += 4;
                v = get_unaligned((const u32 *) (ip + m_len)) ^
                    get_unaligned((const u32 *) (m_pos + m_len));
                if (v != 0)
                    break;
                m_len += 4;
                v = get_unaligned((const u32 *) (ip + m_len)) ^
                    get_unaligned((const u32 *) (m_pos + m_len));
                if (unlikely(ip + m_len >= ip_end))
                    goto m_len_done;
            } while (v == 0);
        }
#  if defined(__LITTLE_ENDIAN)
        m_len += (unsigned) __builtin_ctz(v) / 8;
#  elif defined(__BIG_ENDIAN)
        m_len += (unsigned) __builtin_clz(v) / 8;
#  else
#    error "missing endian definition"
#  endif
#else
        if (unlikely(ip[m_len] == m_pos[m_len])) {
            do {
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (ip[m_len] != m_pos[m_len])
                    break;
                m_len += 1;
                if (unlikely(ip + m_len >= ip_end))
                    goto m_len_done;
            } while (ip[m_len] == m_pos[m_len]);
        }
#endif
        }
 m_len_done:

        m_off = ip - m_pos;
        ip += m_len;
        ii = ip;
        if (m_len <= M2_MAX_LEN && m_off <= M2_MAX_OFFSET) {
            m_off -= 1;
            *op++ = (((m_len - 1) << 5) | ((m_off & 7) << 2));
            *op++ = (m_off >> 3);
        } else if (m_off <= M3_MAX_OFFSET) {
            m_off -= 1;
            if (m_len <= M3_MAX_LEN)
                *op++ = (M3_MARKER | (m_len - 2));
            else {
                m_len -= M3_MAX_LEN;
                *op++ = M3_MARKER | 0;
                while (unlikely(m_len > 255)) {
                    m_len -= 255;
                    *op++ = 0;
                }
                *op++ = (m_len);
            }
            *op++ = (m_off << 2);
            *op++ = (m_off >> 6);
        } else {
            m_off -= 0x4000;
            if (m_len <= M4_MAX_LEN)
                *op++ = (M4_MARKER | ((m_off >> 11) & 8)
                             | (m_len - 2));
            else {
                m_len -= M4_MAX_LEN;
                *op++ = (M4_MARKER | ((m_off >> 11) & 8));
                while (unlikely(m_len > 255)) {
                    m_len -= 255;
                    *op++ = 0;
                }
                *op++ = (m_len);
            }
            *op++ = (m_off << 2);
            *op++ = (m_off >> 6);
        }
        goto next;
    }
    *out_len = op - out;
    return in_end - (ii - ti);
}

int lzo1x_1_compress(const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t *out_len,
                     void *wrkmem)
{
    const unsigned char *ip = in;
    unsigned char *op = out;
    size_t l = in_len;
    size_t t = 0;

    while (l > 20) {
        size_t ll = l <= (M4_MAX_OFFSET + 1) ? l : (M4_MAX_OFFSET + 1);
        uintptr_t ll_end = (uintptr_t) ip + ll;
        if ((ll_end + ((t + ll) >> 5)) <= ll_end)
            break;
        BUILD_BUG_ON(D_SIZE * sizeof(lzo_dict_t) > LZO1X_1_MEM_COMPRESS);
        memset(wrkmem, 0, D_SIZE * sizeof(lzo_dict_t));
        t = lzo1x_1_do_compress(ip, ll, op, out_len, t, wrkmem);
        ip += ll;
        op += *out_len;
        l  -= ll;
    }
    t += l;

    if (t > 0) {
        const unsigned char *ii = in + in_len - t;

        if (op == out && t <= 238) {
            *op++ = (17 + t);
        } else if (t <= 3) {
            op[-2] |= t;
        } else if (t <= 18) {
            *op++ = (t - 3);
        } else {
            size_t tt = t - 18;
            *op++ = 0;
            while (tt > 255) {
                tt -= 255;
                *op++ = 0;
            }
            *op++ = tt;
        }
        if (t >= 16) do {
            COPY8(op, ii);
            COPY8(op + 8, ii + 8);
            op += 16;
            ii += 16;
            t -= 16;
        } while (t >= 16);
        if (t > 0) do {
            *op++ = *ii++;
        } while (--t > 0);
    }

    *op++ = M4_MARKER | 1;
    *op++ = 0;
    *op++ = 0;

    *out_len = op - out;
    return LZO_E_OK;
}

/*
 *  LZO1X Decompressor from LZO
 *
 *  Copyright (C) 1996-2012 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for Linux kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */

#define HAVE_IP(x)     ((size_t)(ip_end - ip) >= (size_t)(x))
#define HAVE_OP(x)     ((size_t)(op_end - op) >= (size_t)(x))
#define NEED_IP(x)     if (!HAVE_IP(x)) goto input_overrun
#define NEED_OP(x)     if (!HAVE_OP(x)) goto output_overrun
#define TEST_LB(m_pos) if ((m_pos) < out) goto lookbehind_overrun

/* This MAX_255_COUNT is the maximum number of times we can add 255 to a base
 * count without overflowing an integer. The multiply will overflow when
 * multiplying 255 by more than MAXINT/255. The sum will overflow earlier
 * depending on the base count. Since the base count is taken from a u8
 * and a few bits, it is safe to assume that it will always be lower than
 * or equal to 2*255, thus we can always prevent any overflow by accepting
 * two less 255 steps. See Documentation/lzo.txt for more information.
 */
#define MAX_255_COUNT      ((((size_t)~0) / 255) - 2)

int lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
                          unsigned char *out, size_t *out_len)
{
    unsigned char *op;
    const unsigned char *ip;
    size_t t, next;
    size_t state = 0;
    const unsigned char *m_pos;
    const unsigned char * const ip_end = in + in_len;
    unsigned char * const op_end = out + *out_len;

    op = out;
    ip = in;

    if (unlikely(in_len < 3))
        goto input_overrun;
    if (*ip > 17) {
        t = *ip++ - 17;
        if (t < 4) {
            next = t;
            goto match_next;
        }
        goto copy_literal_run;
    }

    for (;;) {
        t = *ip++;
        if (t < 16) {
            if (likely(state == 0)) {
                if (unlikely(t == 0)) {
                    size_t offset;
                    const unsigned char *ip_last = ip;

                    while (unlikely(*ip == 0)) {
                        ip++;
                        NEED_IP(1);
                    }
                    offset = ip - ip_last;
                    if (unlikely(offset > MAX_255_COUNT))
                        return LZO_E_ERROR;

                    offset = (offset << 8) - offset;
                    t += offset + 15 + *ip++;
                }
                t += 3;
 copy_literal_run:
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
                if (likely(HAVE_IP(t + 15) && HAVE_OP(t + 15))) {
                    const unsigned char *ie = ip + t;
                    unsigned char *oe = op + t;
                    do {
                        COPY8(op, ip);
                        op += 8;
                        ip += 8;
                        COPY8(op, ip);
                        op += 8;
                        ip += 8;
                    } while (ip < ie);
                    ip = ie;
                    op = oe;
                } else
#endif
                {
                    NEED_OP(t);
                    NEED_IP(t + 3);
                    do {
                        *op++ = *ip++;
                    } while (--t > 0);
                }
                state = 4;
                continue;
            } else if (state != 4) {
                next = t & 3;
                m_pos = op - 1;
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;
                TEST_LB(m_pos);
                NEED_OP(2);
                op[0] = m_pos[0];
                op[1] = m_pos[1];
                op += 2;
                goto match_next;
            } else {
                next = t & 3;
                m_pos = op - (1 + M2_MAX_OFFSET);
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;
                t = 3;
            }
        } else if (t >= 64) {
            next = t & 3;
            m_pos = op - 1;
            m_pos -= (t >> 2) & 7;
            m_pos -= *ip++ << 3;
            t = (t >> 5) - 1 + (3 - 1);
        } else if (t >= 32) {
            t = (t & 31) + (3 - 1);
            if (unlikely(t == 2)) {
                size_t offset;
                const unsigned char *ip_last = ip;

                while (unlikely(*ip == 0)) {
                    ip++;
                    NEED_IP(1);
                }
                offset = ip - ip_last;
                if (unlikely(offset > MAX_255_COUNT))
                    return LZO_E_ERROR;

                offset = (offset << 8) - offset;
                t += offset + 31 + *ip++;
                NEED_IP(2);
            }
            m_pos = op - 1;
            next = get_unaligned_le16(ip);
            ip += 2;
            m_pos -= next >> 2;
            next &= 3;
        } else {
            m_pos = op;
            m_pos -= (t & 8) << 11;
            t = (t & 7) + (3 - 1);
            if (unlikely(t == 2)) {
                size_t offset;
                const unsigned char *ip_last = ip;

                while (unlikely(*ip == 0)) {
                    ip++;
                    NEED_IP(1);
                }
                offset = ip - ip_last;
                if (unlikely(offset > MAX_255_COUNT))
                    return LZO_E_ERROR;

                offset = (offset << 8) - offset;
                t += offset + 7 + *ip++;
                NEED_IP(2);
            }
            next = get_unaligned_le16(ip);
            ip += 2;
            m_pos -= next >> 2;
            next &= 3;
            if (m_pos == op)
                goto eof_found;
            m_pos -= 0x4000;
        }
        TEST_LB(m_pos);
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
        if (op - m_pos >= 8) {
            unsigned char *oe = op + t;
            if (likely(HAVE_OP(t + 15))) {
                do {
                    COPY8(op, m_pos);
                    op += 8;
                    m_pos += 8;
                    COPY8(op, m_pos);
                    op += 8;
                    m_pos += 8;
                } while (op < oe);
                op = oe;
                if (HAVE_IP(6)) {
                    state = next;
                    COPY4(op, ip);
                    op += next;
                    ip += next;
                    continue;
                }
            } else {
                NEED_OP(t);
                do {
                    *op++ = *m_pos++;
                } while (op < oe);
            }
        } else
#endif
        {
            unsigned char *oe = op + t;
            NEED_OP(t);
            op[0] = m_pos[0];
            op[1] = m_pos[1];
            op += 2;
            m_pos += 2;
            do {
                *op++ = *m_pos++;
            } while (op < oe);
        }
        match_next:
        state = next;
        t = next;
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
        if (likely(HAVE_IP(6) && HAVE_OP(4))) {
            COPY4(op, ip);
            op += t;
            ip += t;
        } else
#endif
        {
            NEED_IP(t + 3);
            NEED_OP(t);
            while (t > 0) {
                *op++ = *ip++;
                t--;
            }
        }
    }

 eof_found:
    *out_len = op - out;
    return (t != 3       ? LZO_E_ERROR :
            ip == ip_end ? LZO_E_OK :
            ip <  ip_end ? LZO_E_INPUT_NOT_CONSUMED : LZO_E_INPUT_OVERRUN);

 input_overrun:
    *out_len = op - out;
    return LZO_E_INPUT_OVERRUN;

 output_overrun:
    *out_len = op - out;
    return LZO_E_OUTPUT_OVERRUN;

 lookbehind_overrun:
    *out_len = op - out;
    return LZO_E_LOOKBEHIND_OVERRUN;
}
