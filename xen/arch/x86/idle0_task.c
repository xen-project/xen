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

/*
 * per-CPU TSS segments. Threads are completely 'soft' on Linux,
 * no more per-task TSS's. The TSS size is kept cacheline-aligned
 * so they are allowed to end up in the .data.cacheline_aligned
 * section. Since TSS's are completely CPU-local, we want them
 * on exact cacheline boundaries, to eliminate cacheline ping-pong.
 */ 
struct tss_struct init_tss[NR_CPUS] __cacheline_aligned;
