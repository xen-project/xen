#include <asm/atomic.h>
#include <asm/rwlock.h>

#if defined(CONFIG_SMP)
asm(
".align  4\n"
".globl  __write_lock_failed\n"
"__write_lock_failed:\n"
"        " LOCK "addl    $" RW_LOCK_BIAS_STR ",(%"__OP"ax)\n"
"1:      rep; nop\n"
"        cmpl    $" RW_LOCK_BIAS_STR ",(%"__OP"ax)\n"
"        jne     1b\n"
"        " LOCK "subl    $" RW_LOCK_BIAS_STR ",(%"__OP"ax)\n"
"        jnz     __write_lock_failed\n"
"        ret\n"

".align  4\n"
".globl  __read_lock_failed\n"
"__read_lock_failed:\n"
"        lock ; incl     (%"__OP"ax)\n"
"1:      rep; nop\n"
"        cmpl    $1,(%"__OP"ax)\n"
"        js      1b\n"
"        lock ; decl     (%"__OP"ax)\n"
"        js      __read_lock_failed\n"
"        ret\n"
);
#endif
