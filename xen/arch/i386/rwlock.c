#include <asm/atomic.h>
#include <asm/rwlock.h>

#if defined(CONFIG_SMP)
asm(
".align  4\n"
".globl  __write_lock_failed\n"
"__write_lock_failed:\n"
"        " LOCK "addl    $" RW_LOCK_BIAS_STR ",(%eax)\n"
"1:      rep; nop\n"
"        cmpl    $" RW_LOCK_BIAS_STR ",(%eax)\n"
"        jne     1b\n"
"        " LOCK "subl    $" RW_LOCK_BIAS_STR ",(%eax)\n"
"        jnz     __write_lock_failed\n"
"        ret\n"

".align  4\n"
".globl  __read_lock_failed\n"
"__read_lock_failed:\n"
"        lock ; incl     (%eax)\n"
"1:      rep; nop\n"
"        cmpl    $1,(%eax)\n"
"        js      1b\n"
"        lock ; decl     (%eax)\n"
"        js      __read_lock_failed\n"
"        ret\n"
);
#endif
