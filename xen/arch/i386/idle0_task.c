#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/desc.h>

/*
 * Initial task structure. XXX KAF: To get this 8192-byte aligned without
 * linker tricks I copy it into aligned BSS area at boot time.
 * Actual name idle0_task_union now declared in boot.S.
 */
struct task_struct first_task_struct = IDLE0_TASK(idle0_task_union.task);

/*
 * per-CPU TSS segments. Threads are completely 'soft' on Linux,
 * no more per-task TSS's. The TSS size is kept cacheline-aligned
 * so they are allowed to end up in the .data.cacheline_aligned
 * section. Since TSS's are completely CPU-local, we want them
 * on exact cacheline boundaries, to eliminate cacheline ping-pong.
 */ 
struct tss_struct init_tss[NR_CPUS] __cacheline_aligned = { [0 ... NR_CPUS-1] = INIT_TSS };

