/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Last Level Cache (LLC) coloring common header
 *
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 * Copyright (C) 2024, Minerva Systems SRL
 */
#ifndef __XEN_LLC_COLORING_H__
#define __XEN_LLC_COLORING_H__

struct domain;

#ifdef CONFIG_LLC_COLORING
void llc_coloring_init(void);
void dump_llc_coloring_info(void);
void domain_dump_llc_colors(const struct domain *d);
#else
static inline void llc_coloring_init(void) {}
static inline void dump_llc_coloring_info(void) {}
static inline void domain_dump_llc_colors(const struct domain *d) {}
#endif

unsigned int get_llc_way_size(void);
void arch_llc_coloring_init(void);

#endif /* __XEN_LLC_COLORING_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
