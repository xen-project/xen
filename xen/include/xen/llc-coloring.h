/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Last Level Cache (LLC) coloring common header
 *
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 * Copyright (C) 2024, Minerva Systems SRL
 */
#ifndef __XEN_LLC_COLORING_H__
#define __XEN_LLC_COLORING_H__

#include <xen/types.h>

struct domain;
struct page_info;
struct xen_domctl_set_llc_colors;

#ifdef CONFIG_LLC_COLORING
extern bool llc_coloring_enabled;

void llc_coloring_init(void);
void dump_llc_coloring_info(void);
void domain_dump_llc_colors(const struct domain *d);
void domain_llc_coloring_free(struct domain *d);
#else
#define llc_coloring_enabled false

static inline void llc_coloring_init(void) {}
static inline void dump_llc_coloring_info(void) {}
static inline void domain_dump_llc_colors(const struct domain *d) {}
static inline void domain_llc_coloring_free(struct domain *d) {}
#endif

unsigned int get_llc_way_size(void);
void arch_llc_coloring_init(void);
int dom0_set_llc_colors(struct domain *d);
int domain_set_llc_colors(struct domain *d,
                          const struct xen_domctl_set_llc_colors *config);
int domain_set_llc_colors_from_str(struct domain *d, const char *str);
unsigned int page_to_llc_color(const struct page_info *pg);
unsigned int get_max_nr_llc_colors(void);

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
