#include <asm/atomic.h>
#include <asm/rwlock.h>

#if defined(CONFIG_SMP)
asm(
"
.align  4
.globl  __write_lock_failed
__write_lock_failed:
        " LOCK "addl    $" RW_LOCK_BIAS_STR ",(%eax)
1:      rep; nop
        cmpl    $" RW_LOCK_BIAS_STR ",(%eax)
        jne     1b

        " LOCK "subl    $" RW_LOCK_BIAS_STR ",(%eax)
        jnz     __write_lock_failed
        ret


.align  4
.globl  __read_lock_failed
__read_lock_failed:
        lock ; incl     (%eax)
1:      rep; nop
        cmpl    $1,(%eax)
        js      1b

        lock ; decl     (%eax)
        js      __read_lock_failed
        ret
"
);
#endif
