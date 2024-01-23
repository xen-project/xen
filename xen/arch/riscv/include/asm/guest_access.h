/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_RISCV_GUEST_ACCESS_H__
#define __ASM_RISCV_GUEST_ACCESS_H__

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len);
unsigned long raw_copy_from_guest(void *to, const void *from, unsigned len);
unsigned long raw_clear_guest(void *to, unsigned int len);

#define __raw_copy_to_guest raw_copy_to_guest
#define __raw_copy_from_guest raw_copy_from_guest
#define __raw_clear_guest raw_clear_guest

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
/* All RISCV guests are paging mode external and hence safe */
#define guest_handle_okay(hnd, nr) (1)
#define guest_handle_subrange_okay(hnd, first, last) (1)

#endif /* __ASM_RISCV_GUEST_ACCESS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
