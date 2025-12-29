/* SPDX-License-Identifier:  GPL-2.0-only */

#ifndef ASM_RISCV_VSBI_H
#define ASM_RISCV_VSBI_H

struct cpu_user_regs;

struct vsbi_ext {
    const char *name;
    unsigned long eid_start;
    unsigned long eid_end;
    int (*handler)(unsigned long eid, unsigned long fid,
                   struct cpu_user_regs *regs);
};

/* Ranges (start and end) are inclusive within an extension */
#define VSBI_EXT(ext, start, end, handle)           \
static const struct vsbi_ext vsbi_ext_##ext __used  \
__section(".vsbi.exts") = {                         \
    .name = #ext,                                   \
    .eid_start = start,                             \
    .eid_end = end,                                 \
    .handler = handle,                              \
};

void vsbi_handle_ecall(struct cpu_user_regs *regs);
const struct vsbi_ext *vsbi_find_extension(unsigned long eid);

void check_vsbi_ext_ranges(void);

#endif
