/******************************************************************************
 * xenoprof.h
 * 
 * Xenoprof: Xenoprof enables performance profiling in Xen
 * 
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 */

#ifndef __XEN_XENOPROF_H__
#define __XEN_XENOPROF_H__

#include <xen/inttypes.h>
#include <asm/xenoprof.h>

#define PMU_OWNER_NONE          0
#define PMU_OWNER_XENOPROF      1
#define PMU_OWNER_HVM           2

#ifdef CONFIG_XENOPROF

struct domain;
struct vcpu;
struct cpu_user_regs;

int acquire_pmu_ownership(int pmu_ownership);
void release_pmu_ownership(int pmu_ownership);

int is_active(struct domain *d);
int is_passive(struct domain *d);
void free_xenoprof_pages(struct domain *d);

int xenoprof_add_trace(struct vcpu *, uint64_t pc, int mode);

void xenoprof_log_event(struct vcpu *, const struct cpu_user_regs *,
                        uint64_t pc, int mode, int event);

#else
static inline int acquire_pmu_ownership(int pmu_ownership)
{
    return 1;
}

static inline void release_pmu_ownership(int pmu_ownership)
{
}
#endif /* CONFIG_XENOPROF */

#endif  /* __XEN__XENOPROF_H__ */
