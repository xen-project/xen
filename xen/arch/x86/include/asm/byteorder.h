#ifndef __ASM_X86_BYTEORDER_H__
#define __ASM_X86_BYTEORDER_H__

#include <xen/types.h>
#include <xen/compiler.h>

static inline attr_const uint32_t ___arch__swab32(uint32_t x)
{
    asm("bswap %0" : "=r" (x) : "0" (x));
    return x;
}

static inline attr_const uint64_t ___arch__swab64(uint64_t x)
{ 
    asm ( "bswap %0" : "+r" (x) );
    return x;
} 

/* Do not define swab16.  Gcc is smart enough to recognize "C" version and
   convert it into rotation or exhange.  */

#define __arch__swab64(x) ___arch__swab64(x)
#define __arch__swab32(x) ___arch__swab32(x)

#define __BYTEORDER_HAS_U64__

#include <xen/byteorder/little_endian.h>

#endif /* __ASM_X86_BYTEORDER_H__ */
