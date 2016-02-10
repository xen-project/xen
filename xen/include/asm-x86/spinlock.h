#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#define _raw_read_unlock(l) \
    BUILD_BUG_ON(sizeof((l)->lock) != 4); /* Clang doesn't support %z in asm. */ \
    asm volatile ( "lock; decl %0" : "+m" ((l)->lock) :: "memory" )

/*
 * On x86 the only reordering is of reads with older writes.  In the
 * lock case, the read in observe_head() can only be reordered with
 * writes that precede it, and moving a write _into_ a locked section
 * is OK.  In the release case, the write in add_sized() can only be
 * reordered with reads that follow it, and hoisting a read _into_ a
 * locked region is OK.
 */
#define arch_lock_acquire_barrier() barrier()
#define arch_lock_release_barrier() barrier()

#define arch_lock_relax() cpu_relax()
#define arch_lock_signal()

#endif /* __ASM_SPINLOCK_H */
