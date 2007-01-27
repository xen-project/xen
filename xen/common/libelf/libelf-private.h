#ifdef __XEN__

#include <xen/string.h>
#include <xen/lib.h>
#include <public/elfnote.h>
#include <public/libelf.h>

#define elf_msg(elf, fmt, args ... ) \
	if (elf->verbose) printk(fmt, ## args )
#define elf_err(elf, fmt, args ... ) \
	printk(fmt, ## args )

#define strtoull(str, end, base) simple_strtoull(str, end, base)
#define bswap_16(x) \
     ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define bswap_32(x) \
     (  (((x) & 0xff000000) >> 24)  \
      | (((x) & 0x00ff0000) >>  8)  \
      | (((x) & 0x0000ff00) <<  8)  \
      | (((x) & 0x000000ff) << 24))
#define bswap_64(x) \
     (  (((x) & 0xff00000000000000ull) >> 56)  \
      | (((x) & 0x00ff000000000000ull) >> 40)  \
      | (((x) & 0x0000ff0000000000ull) >> 24)  \
      | (((x) & 0x000000ff00000000ull) >> 8)   \
      | (((x) & 0x00000000ff000000ull) << 8)   \
      | (((x) & 0x0000000000ff0000ull) << 24)  \
      | (((x) & 0x000000000000ff00ull) << 40)  \
      | (((x) & 0x00000000000000ffull) << 56))

#else /* !__XEN__ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include <xen/elfnote.h>
#include <xen/libelf.h>

#include "xenctrl.h"
#include "xc_private.h"

#define elf_msg(elf, fmt, args ... ) \
	if (elf->log && elf->verbose) fprintf(elf->log, fmt , ## args )
#define elf_err(elf, fmt, args ... ) do {                 \
	if (elf->log)                                     \
            fprintf(elf->log, fmt , ## args );            \
        xc_set_error(XC_INVALID_KERNEL, fmt , ## args );  \
	} while (0)

#endif
