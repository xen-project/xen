#ifndef __X86_ALTERNATIVE_H__
#define __X86_ALTERNATIVE_H__

#include <asm/nops.h>

#ifdef __ASSEMBLY__
.macro altinstruction_entry orig alt feature orig_len alt_len
        .long \orig - .
        .long \alt - .
        .word \feature
        .byte \orig_len
        .byte \alt_len
.endm
#else
#include <xen/types.h>

struct alt_instr {
    s32 instr_offset;       /* original instruction */
    s32 repl_offset;        /* offset to replacement instruction */
    u16 cpuid;              /* cpuid bit set for replacement */
    u8  instrlen;           /* length of original instruction */
    u8  replacementlen;     /* length of new instruction, <= instrlen */
};

extern void alternative_instructions(void);

#define OLDINSTR(oldinstr)      "661:\n\t" oldinstr "\n662:\n"

#define b_replacement(number)   "663"#number
#define e_replacement(number)   "664"#number

#define alt_slen "662b-661b"
#define alt_rlen(number) e_replacement(number)"f-"b_replacement(number)"f"

#define ALTINSTR_ENTRY(feature, number)                                       \
        " .long 661b - .\n"                             /* label           */ \
        " .long " b_replacement(number)"f - .\n"        /* new instruction */ \
        " .word " __stringify(feature) "\n"             /* feature bit     */ \
        " .byte " alt_slen "\n"                         /* source len      */ \
        " .byte " alt_rlen(number) "\n"                 /* replacement len */

#define DISCARD_ENTRY(number)                           /* rlen <= slen */    \
        " .byte 0xff + (" alt_rlen(number) ") - (" alt_slen ")\n"

#define ALTINSTR_REPLACEMENT(newinstr, feature, number) /* replacement */     \
        b_replacement(number)":\n\t" newinstr "\n" e_replacement(number) ":\n\t"

/* alternative assembly primitive: */
#define ALTERNATIVE(oldinstr, newinstr, feature)                        \
        OLDINSTR(oldinstr)                                              \
        ".pushsection .altinstructions,\"a\"\n"                         \
        ALTINSTR_ENTRY(feature, 1)                                      \
        ".popsection\n"                                                 \
        ".pushsection .discard,\"aw\",@progbits\n"                      \
        DISCARD_ENTRY(1)                                                \
        ".popsection\n"                                                 \
        ".pushsection .altinstr_replacement, \"ax\"\n"                  \
        ALTINSTR_REPLACEMENT(newinstr, feature, 1)                      \
        ".popsection"

/*
 * Alternative instructions for different CPU types or capabilities.
 *
 * This allows to use optimized instructions even on generic binary
 * kernels.
 *
 * length of oldinstr must be longer or equal the length of newinstr
 * It can be padded with nops as needed.
 *
 * For non barrier like inlines please define new variants
 * without volatile and memory clobber.
 */
#define alternative(oldinstr, newinstr, feature)                        \
        asm volatile (ALTERNATIVE(oldinstr, newinstr, feature) : : : "memory")

#endif  /*  __ASSEMBLY__  */

#endif /* __X86_ALTERNATIVE_H__ */
