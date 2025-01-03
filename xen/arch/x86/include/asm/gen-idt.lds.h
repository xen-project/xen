/*
 * Linker file fragment to help format the IDT correctly
 *
 * The IDT, having grown compatibly since the 16 bit days, has the entrypoint
 * address field split into 3.  x86 ELF lacks the @lo/@hi/etc relocation forms
 * commonly found in other architectures for accessing a part of a resolved
 * symbol address.
 *
 * However, the linker can perform the necessary calculations and provide them
 * under new symbol names.  We use this to generate the low and next 16 bits
 * of the address for each handler.
 *
 * The upper 32 bits are always a constant as Xen's .text/data/rodata sits in
 * a single aligned 1G range, so do not need calculating in this manner.
 */
#ifndef X86_IDT_GEN_LDS_H
#define X86_IDT_GEN_LDS_H

#define GEN(vec, sym, dpl, auto)                                        \
    PROVIDE_HIDDEN(IDT_ ## sym ## _ADDR1 = ABSOLUTE(((sym) & 0xffff))); \
    PROVIDE_HIDDEN(IDT_ ## sym ## _ADDR2 = ABSOLUTE((((sym) >> 16) & 0xffff)))

#include <asm/gen-idt.h>

#undef GEN

#endif /* X86_IDT_GEN_LDS_H */
