/*
 *  lzo.c -- LZO1X Compressor from MiniLZO
 *
 *  Copyright (C) 1996-2005 Markus F.X.J. Oberhumer <markus@oberhumer.com>
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
 *  Copyright (C) 1996-2005 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */

#define LZO_VERSION  0x2020
#define LZO_VERSION_STRING "2.02"
#define LZO_VERSION_DATE "Oct 17 2005"

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

#define D_BITS  14
#define D_MASK  ((1u << D_BITS) - 1)
#define D_HIGH  ((D_MASK >> 1) + 1)

#define DX2(p, s1, s2) (((((size_t)((p)[2]) << (s2)) ^ (p)[1]) \
       << (s1)) ^ (p)[0])
#define DX3(p, s1, s2, s3) ((DX2((p)+1, s2, s3) << (s1)) ^ (p)[0])

/*
 *  LZO1X Compressor from MiniLZO
 *
 *  Copyright (C) 1996-2005 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */

#include <xen/types.h>
#include <xen/lzo.h>
#define get_unaligned(_p) (*(_p))
#define put_unaligned(_val,_p) (*(_p)=_val)
#define get_unaligned_le16(_p) (*(u16 *)(_p))

static noinline size_t
_lzo1x_1_do_compress(const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t *out_len, void *wrkmem)
{
    const unsigned char * const in_end = in + in_len;
    const unsigned char * const ip_end = in + in_len - M2_MAX_LEN - 5;
    const unsigned char ** const dict = wrkmem;
    const unsigned char *ip = in, *ii = ip;
    const unsigned char *end, *m, *m_pos;
    size_t m_off, m_len, dindex;
    unsigned char *op = out;

    ip += 4;

    for (;;) {
        dindex = ((size_t)(0x21 * DX3(ip, 5, 5, 6)) >> 5) & D_MASK;
        m_pos = dict[dindex];

        if (m_pos < in)
            goto literal;

        if (ip == m_pos || ((size_t)(ip - m_pos) > M4_MAX_OFFSET))
            goto literal;

        m_off = ip - m_pos;
        if (m_off <= M2_MAX_OFFSET || m_pos[3] == ip[3])
            goto try_match;

        dindex = (dindex & (D_MASK & 0x7ff)) ^ (D_HIGH | 0x1f);
        m_pos = dict[dindex];

        if (m_pos < in)
            goto literal;

        if (ip == m_pos || ((size_t)(ip - m_pos) > M4_MAX_OFFSET))
            goto literal;

        m_off = ip - m_pos;
        if (m_off <= M2_MAX_OFFSET || m_pos[3] == ip[3])
            goto try_match;

        goto literal;

    try_match:
        if (get_unaligned((const unsigned short *)m_pos)
            == get_unaligned((const unsigned short *)ip)) {
            if (likely(m_pos[2] == ip[2]))
                goto match;
        }

    literal:
        dict[dindex] = ip;
        ++ip;
        if (unlikely(ip >= ip_end))
            break;
        continue;

    match:
        dict[dindex] = ip;
        if (ip != ii) {
            size_t t = ip - ii;

            if (t <= 3) {
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
            do {
                *op++ = *ii++;
            } while (--t > 0);
        }

        ip += 3;
        if (m_pos[3] != *ip++ || m_pos[4] != *ip++
            || m_pos[5] != *ip++ || m_pos[6] != *ip++
            || m_pos[7] != *ip++ || m_pos[8] != *ip++) {
            --ip;
            m_len = ip - ii;

            if (m_off <= M2_MAX_OFFSET) {
                m_off -= 1;
                *op++ = (((m_len - 1) << 5)
                         | ((m_off & 7) << 2));
                *op++ = (m_off >> 3);
            } else if (m_off <= M3_MAX_OFFSET) {
                m_off -= 1;
                *op++ = (M3_MARKER | (m_len - 2));
                goto m3_m4_offset;
            } else {
                m_off -= 0x4000;

                *op++ = (M4_MARKER | ((m_off & 0x4000) >> 11)
                         | (m_len - 2));
                goto m3_m4_offset;
            }
        } else {
            end = in_end;
            m = m_pos + M2_MAX_LEN + 1;

            while (ip < end && *m == *ip) {
                m++;
                ip++;
            }
            m_len = ip - ii;

            if (m_off <= M3_MAX_OFFSET) {
                m_off -= 1;
                if (m_len <= 33) {
                    *op++ = (M3_MARKER | (m_len - 2));
                } else {
                    m_len -= 33;
                    *op++ = M3_MARKER | 0;
                    goto m3_m4_len;
                }
            } else {
                m_off -= 0x4000;
                if (m_len <= M4_MAX_LEN) {
                    *op++ = (M4_MARKER
                             | ((m_off & 0x4000) >> 11)
                             | (m_len - 2));
                } else {
                    m_len -= M4_MAX_LEN;
                    *op++ = (M4_MARKER
                             | ((m_off & 0x4000) >> 11));
                m3_m4_len:
                    while (m_len > 255) {
                        m_len -= 255;
                        *op++ = 0;
                    }

                    *op++ = (m_len);
                }
            }
        m3_m4_offset:
            *op++ = ((m_off & 63) << 2);
            *op++ = (m_off >> 6);
        }

        ii = ip;
        if (unlikely(ip >= ip_end))
            break;
    }

    *out_len = op - out;
    return in_end - ii;
}

int lzo1x_1_compress(const unsigned char *in, size_t in_len, unsigned char *out,
                     size_t *out_len, void *wrkmem)
{
    const unsigned char *ii;
    unsigned char *op = out;
    size_t t;

    if (unlikely(in_len <= M2_MAX_LEN + 5)) {
        t = in_len;
    } else {
        t = _lzo1x_1_do_compress(in, in_len, op, out_len, wrkmem);
        op += *out_len;
    }

    if (t > 0) {
        ii = in + in_len - t;

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
        do {
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
 *  LZO1X Decompressor from MiniLZO
 *
 *  Copyright (C) 1996-2005 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */

#define HAVE_IP(x, ip_end, ip) ((size_t)(ip_end - ip) < (x))
#define HAVE_OP(x, op_end, op) ((size_t)(op_end - op) < (x))
#define HAVE_LB(m_pos, out, op) (m_pos < out || m_pos >= op)

#define COPY4(dst, src) \
  put_unaligned(get_unaligned((const u32 *)(src)), (u32 *)(dst))

int lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
                          unsigned char *out, size_t *out_len)
{
    const unsigned char * const ip_end = in + in_len;
    unsigned char * const op_end = out + *out_len;
    const unsigned char *ip = in, *m_pos;
    unsigned char *op = out;
    size_t t;

    *out_len = 0;

    if (*ip > 17) {
        t = *ip++ - 17;
        if (t < 4)
            goto match_next;
        if (HAVE_OP(t, op_end, op))
            goto output_overrun;
        if (HAVE_IP(t + 1, ip_end, ip))
            goto input_overrun;
        do {
            *op++ = *ip++;
        } while (--t > 0);
        goto first_literal_run;
    }

    while ((ip < ip_end)) {
        t = *ip++;
        if (t >= 16)
            goto match;
        if (t == 0) {
            if (HAVE_IP(1, ip_end, ip))
                goto input_overrun;
            while (*ip == 0) {
                t += 255;
                ip++;
                if (HAVE_IP(1, ip_end, ip))
                    goto input_overrun;
            }
            t += 15 + *ip++;
        }
        if (HAVE_OP(t + 3, op_end, op))
            goto output_overrun;
        if (HAVE_IP(t + 4, ip_end, ip))
            goto input_overrun;

        COPY4(op, ip);
        op += 4;
        ip += 4;
        if (--t > 0) {
            if (t >= 4) {
                do {
                    COPY4(op, ip);
                    op += 4;
                    ip += 4;
                    t -= 4;
                } while (t >= 4);
                if (t > 0) {
                    do {
                        *op++ = *ip++;
                    } while (--t > 0);
                }
            } else {
                do {
                    *op++ = *ip++;
                } while (--t > 0);
            }
        }

    first_literal_run:
        t = *ip++;
        if (t >= 16)
            goto match;
        m_pos = op - (1 + M2_MAX_OFFSET);
        m_pos -= t >> 2;
        m_pos -= *ip++ << 2;

        if (HAVE_LB(m_pos, out, op))
            goto lookbehind_overrun;

        if (HAVE_OP(3, op_end, op))
            goto output_overrun;
        *op++ = *m_pos++;
        *op++ = *m_pos++;
        *op++ = *m_pos;

        goto match_done;

        do {
        match:
            if (t >= 64) {
                m_pos = op - 1;
                m_pos -= (t >> 2) & 7;
                m_pos -= *ip++ << 3;
                t = (t >> 5) - 1;
                if (HAVE_LB(m_pos, out, op))
                    goto lookbehind_overrun;
                if (HAVE_OP(t + 3 - 1, op_end, op))
                    goto output_overrun;
                goto copy_match;
            } else if (t >= 32) {
                t &= 31;
                if (t == 0) {
                    if (HAVE_IP(1, ip_end, ip))
                        goto input_overrun;
                    while (*ip == 0) {
                        t += 255;
                        ip++;
                        if (HAVE_IP(1, ip_end, ip))
                            goto input_overrun;
                    }
                    t += 31 + *ip++;
                }
                m_pos = op - 1;
                m_pos -= get_unaligned_le16(ip) >> 2;
                ip += 2;
            } else if (t >= 16) {
                m_pos = op;
                m_pos -= (t & 8) << 11;

                t &= 7;
                if (t == 0) {
                    if (HAVE_IP(1, ip_end, ip))
                        goto input_overrun;
                    while (*ip == 0) {
                        t += 255;
                        ip++;
                        if (HAVE_IP(1, ip_end, ip))
                            goto input_overrun;
                    }
                    t += 7 + *ip++;
                }
                m_pos -= get_unaligned_le16(ip) >> 2;
                ip += 2;
                if (m_pos == op)
                    goto eof_found;
                m_pos -= 0x4000;
            } else {
                m_pos = op - 1;
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;

                if (HAVE_LB(m_pos, out, op))
                    goto lookbehind_overrun;
                if (HAVE_OP(2, op_end, op))
                    goto output_overrun;

                *op++ = *m_pos++;
                *op++ = *m_pos;
                goto match_done;
            }

            if (HAVE_LB(m_pos, out, op))
                goto lookbehind_overrun;
            if (HAVE_OP(t + 3 - 1, op_end, op))
                goto output_overrun;

            if (t >= 2 * 4 - (3 - 1) && (op - m_pos) >= 4) {
                COPY4(op, m_pos);
                op += 4;
                m_pos += 4;
                t -= 4 - (3 - 1);
                do {
                    COPY4(op, m_pos);
                    op += 4;
                    m_pos += 4;
                    t -= 4;
                } while (t >= 4);
                if (t > 0)
                    do {
                        *op++ = *m_pos++;
                    } while (--t > 0);
            } else {
            copy_match:
                *op++ = *m_pos++;
                *op++ = *m_pos++;
                do {
                    *op++ = *m_pos++;
                } while (--t > 0);
            }
        match_done:
            t = ip[-2] & 3;
            if (t == 0)
                break;
        match_next:
            if (HAVE_OP(t, op_end, op))
                goto output_overrun;
            if (HAVE_IP(t + 1, ip_end, ip))
                goto input_overrun;

            *op++ = *ip++;
            if (t > 1) {
                *op++ = *ip++;
                if (t > 2)
                    *op++ = *ip++;
            }

            t = *ip++;
        } while (ip < ip_end);
    }

    *out_len = op - out;
    return LZO_E_EOF_NOT_FOUND;

 eof_found:
    *out_len = op - out;
    return (ip == ip_end ? LZO_E_OK :
            (ip < ip_end ? LZO_E_INPUT_NOT_CONSUMED : LZO_E_INPUT_OVERRUN));
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
