/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/desc.h>

struct domain idle0_domain = {
    id:          IDLE_DOMAIN_ID,
    d_flags:     1<<DF_IDLETASK,
    refcnt:      ATOMIC_INIT(1)
};

struct exec_domain idle0_exec_domain = {
    processor:   0,
    domain:      &idle0_domain,
    arch:        IDLE0_ARCH_EXEC_DOMAIN
};

struct tss_struct init_tss[NR_CPUS];
