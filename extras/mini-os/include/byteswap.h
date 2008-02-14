#ifndef _BYTESWAP_H_
#define _BYTESWAP_H_

/* Unfortunately not provided by newlib.  */
#define bswap_16(x) \
    ((((x) & 0xff00) >> 8) | (((x) & 0xff) << 8))

#define bswap_32(x) \
    ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#define bswap_64(x) \
    ((((x) & 0xff00000000000000ULL) >> 56) | \
     (((x) & 0x00ff000000000000ULL) >> 40) | \
     (((x) & 0x0000ff0000000000ULL) >> 24) | \
     (((x) & 0x000000ff00000000ULL) >>  8) | \
     (((x) & 0x00000000ff000000ULL) <<  8) | \
     (((x) & 0x0000000000ff0000ULL) << 24) | \
     (((x) & 0x000000000000ff00ULL) << 40) | \
     (((x) & 0x00000000000000ffULL) << 56))

#endif /* _BYTESWAP_H */
