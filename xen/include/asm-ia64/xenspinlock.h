#ifndef _ASM_IA64_XENSPINLOCK_H
#define _ASM_IA64_XENSPINLOCK_H

/*
 * spin_[un]lock_recursive(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * standard spin_[un]lock().
 */
#define _raw_spin_lock_recursive(_lock)            \
    do {                                           \
        int cpu = smp_processor_id();              \
        if ( likely((_lock)->recurse_cpu != cpu) ) \
        {                                          \
            spin_lock(_lock);                      \
            (_lock)->recurse_cpu = cpu;            \
        }                                          \
        (_lock)->recurse_cnt++;                    \
    } while ( 0 )

#define _raw_spin_unlock_recursive(_lock)          \
    do {                                           \
        if ( likely(--(_lock)->recurse_cnt == 0) ) \
        {                                          \
            (_lock)->recurse_cpu = -1;             \
            spin_unlock(_lock);                    \
        }                                          \
    } while ( 0 )
#endif /*  _ASM_IA64_XENSPINLOCK_H */
