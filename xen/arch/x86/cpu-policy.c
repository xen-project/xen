/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/cache.h>
#include <xen/kernel.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/cpu-policy.h>

struct cpu_policy __ro_after_init     raw_cpu_policy;
struct cpu_policy __ro_after_init    host_cpu_policy;
#ifdef CONFIG_PV
struct cpu_policy __ro_after_init  pv_max_cpu_policy;
struct cpu_policy __ro_after_init  pv_def_cpu_policy;
#endif
#ifdef CONFIG_HVM
struct cpu_policy __ro_after_init hvm_max_cpu_policy;
struct cpu_policy __ro_after_init hvm_def_cpu_policy;
#endif
