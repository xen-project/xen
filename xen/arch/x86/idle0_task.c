#include <xen/config.h>
#include <xen/sched.h>
#include <asm/desc.h>

#define IDLE0_TASK(_t)           \
{                                \
    processor:   0,              \
    id:          IDLE_DOMAIN_ID, \
    mm:          IDLE0_MM,       \
    thread:      INIT_THREAD,    \
    flags:       1<<DF_IDLETASK, \
    refcnt:      ATOMIC_INIT(1)  \
}

struct domain idle0_task = IDLE0_TASK(idle0_task);

struct tss_struct init_tss[NR_CPUS];
