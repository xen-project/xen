#include <xen/config.h>
#include <xen/sched.h>
#include <asm/desc.h>

#define IDLE0_EXEC_DOMAIN(_ed,_d)    \
{                                    \
    processor:   0,                  \
    mm:          IDLE0_MM,           \
    thread:      INIT_THREAD,        \
    domain:      (_d)                \
}

#define IDLE0_DOMAIN(_t)             \
{                                    \
    id:          IDLE_DOMAIN_ID,     \
    d_flags:     1<<DF_IDLETASK,     \
    refcnt:      ATOMIC_INIT(1)      \
}

struct domain idle0_domain = IDLE0_DOMAIN(idle0_domain);
struct exec_domain idle0_exec_domain = IDLE0_EXEC_DOMAIN(idle0_exec_domain,
                                                         &idle0_domain);

struct tss_struct init_tss[NR_CPUS];
