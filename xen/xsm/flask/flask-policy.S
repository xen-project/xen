#include <asm/asm_defns.h>

        .section .init.rodata, "a", %progbits

/* const unsigned char xsm_flask_init_policy[] __initconst */
        .global xsm_flask_init_policy
xsm_flask_init_policy:
        .incbin "policy.bin"
.Lend:

        .type xsm_flask_init_policy, %object
        .size xsm_flask_init_policy, . - xsm_flask_init_policy

/* const unsigned int __initconst xsm_flask_init_policy_size */
        .global xsm_flask_init_policy_size
        ASM_INT(xsm_flask_init_policy_size, .Lend - xsm_flask_init_policy)
