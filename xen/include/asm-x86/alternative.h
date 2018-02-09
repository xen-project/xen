#ifndef __X86_ALTERNATIVE_H__
#define __X86_ALTERNATIVE_H__

#include <asm/alternative-asm.h>
#include <asm/nops.h>

#ifndef __ASSEMBLY__
#include <xen/stringify.h>
#include <xen/types.h>

struct __packed alt_instr {
    int32_t  orig_offset;   /* original instruction */
    int32_t  repl_offset;   /* offset to replacement instruction */
    uint16_t cpuid;         /* cpuid bit set for replacement */
    uint8_t  orig_len;      /* length of original instruction */
    uint8_t  repl_len;      /* length of new instruction */
    uint8_t  pad_len;       /* length of build-time padding */
    uint8_t  priv;          /* Private, for use by apply_alternatives() */
};

#define __ALT_PTR(a,f)      ((uint8_t *)((void *)&(a)->f + (a)->f))
#define ALT_ORIG_PTR(a)     __ALT_PTR(a, orig_offset)
#define ALT_REPL_PTR(a)     __ALT_PTR(a, repl_offset)

extern void add_nops(void *insns, unsigned int len);
/* Similar to alternative_instructions except it can be run with IRQs enabled. */
extern void apply_alternatives(struct alt_instr *start, struct alt_instr *end);
extern void alternative_instructions(void);

#define alt_orig_len       "(.LXEN%=_orig_e - .LXEN%=_orig_s)"
#define alt_pad_len        "(.LXEN%=_orig_p - .LXEN%=_orig_e)"
#define alt_total_len      "(.LXEN%=_orig_p - .LXEN%=_orig_s)"
#define alt_repl_s(num)    ".LXEN%=_repl_s"#num
#define alt_repl_e(num)    ".LXEN%=_repl_e"#num
#define alt_repl_len(num)  "(" alt_repl_e(num) " - " alt_repl_s(num) ")"

/* GAS's idea of true is -1, while Clang's idea is 1. */
#ifdef HAVE_AS_NEGATIVE_TRUE
# define AS_TRUE "-"
#else
# define AS_TRUE ""
#endif

#define as_max(a, b) "(("a") ^ ((("a") ^ ("b")) & -("AS_TRUE"(("a") < ("b")))))"

#define OLDINSTR(oldinstr, padding)                              \
    ".LXEN%=_orig_s:\n\t" oldinstr "\n .LXEN%=_orig_e:\n\t"      \
    ".LXEN%=_diff = " padding "\n\t"                             \
    ".skip "AS_TRUE"(.LXEN%=_diff > 0) * .LXEN%=_diff, 0x90\n\t" \
    ".LXEN%=_orig_p:\n\t"

#define OLDINSTR_1(oldinstr, n1)                                 \
    OLDINSTR(oldinstr, alt_repl_len(n1) "-" alt_orig_len)

#define OLDINSTR_2(oldinstr, n1, n2)                             \
    OLDINSTR(oldinstr,                                           \
             as_max((alt_repl_len(n1),                           \
                     alt_repl_len(n2)) "-" alt_orig_len))

#define ALTINSTR_ENTRY(feature, num)                                    \
        " .long .LXEN%=_orig_s - .\n"             /* label           */ \
        " .long " alt_repl_s(num)" - .\n"         /* new instruction */ \
        " .word " __stringify(feature) "\n"       /* feature bit     */ \
        " .byte " alt_orig_len "\n"               /* source len      */ \
        " .byte " alt_repl_len(num) "\n"          /* replacement len */ \
        " .byte " alt_pad_len "\n"                /* padding len     */ \
        " .byte 0\n"                              /* priv            */

#define DISCARD_ENTRY(num)                        /* repl <= total */   \
        " .byte 0xff + (" alt_repl_len(num) ") - (" alt_total_len ")\n"

#define ALTINSTR_REPLACEMENT(newinstr, num)       /* replacement */     \
        alt_repl_s(num)":\n\t" newinstr "\n" alt_repl_e(num) ":\n\t"

/* alternative assembly primitive: */
#define ALTERNATIVE(oldinstr, newinstr, feature)                        \
        OLDINSTR_1(oldinstr, 1)                                         \
        ".pushsection .altinstructions, \"a\", @progbits\n"             \
        ALTINSTR_ENTRY(feature, 1)                                      \
        ".section .discard, \"a\", @progbits\n"                         \
        ".byte " alt_total_len "\n" /* total_len <= 255 */              \
        DISCARD_ENTRY(1)                                                \
        ".section .altinstr_replacement, \"ax\", @progbits\n"           \
        ALTINSTR_REPLACEMENT(newinstr, 1)                               \
        ".popsection\n"

#define ALTERNATIVE_2(oldinstr, newinstr1, feature1, newinstr2, feature2) \
        OLDINSTR_2(oldinstr, 1, 2)                                      \
        ".pushsection .altinstructions, \"a\", @progbits\n"             \
        ALTINSTR_ENTRY(feature1, 1)                                     \
        ALTINSTR_ENTRY(feature2, 2)                                     \
        ".section .discard, \"a\", @progbits\n"                         \
        ".byte " alt_total_len "\n" /* total_len <= 255 */              \
        DISCARD_ENTRY(1)                                                \
        DISCARD_ENTRY(2)                                                \
        ".section .altinstr_replacement, \"ax\", @progbits\n"           \
        ALTINSTR_REPLACEMENT(newinstr1, 1)                              \
        ALTINSTR_REPLACEMENT(newinstr2, 2)                              \
        ".popsection\n"

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

/*
 * Alternative inline assembly with input.
 *
 * Pecularities:
 * No memory clobber here.
 * Argument numbers start with 1.
 * Best is to use constraints that are fixed size (like (%1) ... "r")
 * If you use variable sized constraints like "m" or "g" in the
 * replacement make sure to pad to the worst case length.
 */
#define alternative_input(oldinstr, newinstr, feature, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		      : : input)

/* Like alternative_input, but with a single output argument */
#define alternative_io(oldinstr, newinstr, feature, output, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		      : output : input)

/*
 * This is similar to alternative_io. But it has two features and
 * respective instructions.
 *
 * If CPU has feature2, newinstr2 is used.
 * Otherwise, if CPU has feature1, newinstr1 is used.
 * Otherwise, oldinstr is used.
 */
#define alternative_io_2(oldinstr, newinstr1, feature1, newinstr2,	\
			 feature2, output, input...)			\
	asm volatile(ALTERNATIVE_2(oldinstr, newinstr1, feature1,	\
				   newinstr2, feature2)			\
		     : output : input)

/* Use this macro(s) if you need more than one output parameter. */
#define ASM_OUTPUT2(a...) a

#endif /*  !__ASSEMBLY__  */

#endif /* __X86_ALTERNATIVE_H__ */
