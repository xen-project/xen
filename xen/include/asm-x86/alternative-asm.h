#ifndef _ASM_X86_ALTERNATIVE_ASM_H_
#define _ASM_X86_ALTERNATIVE_ASM_H_

#ifdef __ASSEMBLY__

/*
 * Issue one struct alt_instr descriptor entry (need to put it into
 * the section .altinstructions, see below). This entry contains
 * enough information for the alternatives patching code to patch an
 * instruction. See apply_alternatives().
 */
.macro altinstruction_entry orig repl feature orig_len repl_len pad_len
    .long \orig - .
    .long \repl - .
    .word \feature
    .byte \orig_len
    .byte \repl_len
    .byte \pad_len
    .byte 0 /* priv */
.endm

/* GAS's idea of true is -1, while Clang's idea is 1. */
#ifdef HAVE_AS_NEGATIVE_TRUE
# define as_true(x) (-(x))
#else
# define as_true(x) (x)
#endif

#define decl_orig(insn, padding)                  \
 .L\@_orig_s: insn; .L\@_orig_e:                  \
 .L\@_diff = padding;                             \
 .skip as_true(.L\@_diff > 0) * .L\@_diff, 0x90;  \
 .L\@_orig_p:

#define orig_len               (.L\@_orig_e       -     .L\@_orig_s)
#define pad_len                (.L\@_orig_p       -     .L\@_orig_e)
#define total_len              (.L\@_orig_p       -     .L\@_orig_s)

#define decl_repl(insn, nr)     .L\@_repl_s\()nr: insn; .L\@_repl_e\()nr:
#define repl_len(nr)           (.L\@_repl_e\()nr  -     .L\@_repl_s\()nr)

#define as_max(a, b)           ((a) ^ (((a) ^ (b)) & -as_true((a) < (b))))

.macro ALTERNATIVE oldinstr, newinstr, feature
    decl_orig(\oldinstr, repl_len(1) - orig_len)

    .pushsection .altinstructions, "a", @progbits
    altinstruction_entry .L\@_orig_s, .L\@_repl_s1, \feature, \
        orig_len, repl_len(1), pad_len

    .section .discard, "a", @progbits
    /*
     * Assembler-time checks:
     *   - total_len <= 255
     *   - \newinstr <= total_len
     */
    .byte total_len
    .byte 0xff + repl_len(1) - total_len

    .section .altinstr_replacement, "ax", @progbits

    decl_repl(\newinstr, 1)

    .popsection
.endm

.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
    decl_orig(\oldinstr, as_max(repl_len(1), repl_len(2)) - orig_len)

    .pushsection .altinstructions, "a", @progbits

    altinstruction_entry .L\@_orig_s, .L\@_repl_s1, \feature1, \
        orig_len, repl_len(1), pad_len
    altinstruction_entry .L\@_orig_s, .L\@_repl_s2, \feature2, \
        orig_len, repl_len(2), pad_len

    .section .discard, "a", @progbits
    /*
     * Assembler-time checks:
     *   - total_len <= 255
     *   - \newinstr* <= total_len
     */
    .byte total_len
    .byte 0xff + repl_len(1) - total_len
    .byte 0xff + repl_len(2) - total_len

    .section .altinstr_replacement, "ax", @progbits

    decl_repl(\newinstr1, 1)
    decl_repl(\newinstr2, 2)

    .popsection
.endm

#undef as_max
#undef repl_len
#undef decl_repl
#undef total_len
#undef pad_len
#undef orig_len
#undef decl_orig
#undef as_true

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_ALTERNATIVE_ASM_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
