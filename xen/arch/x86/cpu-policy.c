/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/cache.h>
#include <xen/kernel.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/cpu-policy.h>

struct cpu_policy __read_mostly       raw_cpu_policy;
struct cpu_policy __read_mostly      host_cpu_policy;
#ifdef CONFIG_PV
struct cpu_policy __read_mostly    pv_max_cpu_policy;
struct cpu_policy __read_mostly    pv_def_cpu_policy;
#endif
#ifdef CONFIG_HVM
struct cpu_policy __read_mostly   hvm_max_cpu_policy;
struct cpu_policy __read_mostly   hvm_def_cpu_policy;
#endif
