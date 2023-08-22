#ifndef _ASM_PPC_BITOPS_H
#define _ASM_PPC_BITOPS_H

/* PPC bit number conversion */
#define PPC_BITLSHIFT(be)	(BITS_PER_LONG - 1 - (be))
#define PPC_BIT(bit)		(1UL << PPC_BITLSHIFT(bit))
#define PPC_BITMASK(bs, be)	((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))

#endif /* _ASM_PPC_BITOPS_H */
