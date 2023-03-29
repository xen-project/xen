/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef X86_CPU_POLICY_H
#define X86_CPU_POLICY_H

struct cpu_policy;
struct domain;

extern struct cpu_policy     raw_cpu_policy;
extern struct cpu_policy    host_cpu_policy;
extern struct cpu_policy  pv_max_cpu_policy;
extern struct cpu_policy  pv_def_cpu_policy;
extern struct cpu_policy hvm_max_cpu_policy;
extern struct cpu_policy hvm_def_cpu_policy;

/* Allocate and initialise a CPU policy suitable for the domain. */
int init_domain_cpu_policy(struct domain *d);

#endif /* X86_CPU_POLICY_H */
