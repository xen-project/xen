#ifndef ASM_RISCV_GUEST_LAYOUT_H
#define ASM_RISCV_GUEST_LAYOUT_H

#include <public/xen.h>

#define GUEST_RAM_BANKS   2

/*
 * The way to find the extended regions (to be exposed to the guest as unused
 * address space) relies on the fact that the regions reserved for the RAM
 * below are big enough to also accommodate such regions.
 */
#define GUEST_RAM0_BASE   xen_mk_ullong(0x80000000) /* 2GB of low RAM @ 2GB */
#define GUEST_RAM0_SIZE   xen_mk_ullong(0x80000000)

#define GUEST_RAM1_BASE   xen_mk_ullong(0x0200000000) /* 1016 GB of RAM @ 8GB */
#define GUEST_RAM1_SIZE   xen_mk_ullong(0xFE00000000)

/* TODO: allocate these all dynamically */
#define GUEST_RAM_BANK_BASES   { GUEST_RAM0_BASE, GUEST_RAM1_BASE }
#define GUEST_RAM_BANK_SIZES   { GUEST_RAM0_SIZE, GUEST_RAM1_SIZE }

#endif /* ASM_RISCV_GUEST_LAYOUT_H */
