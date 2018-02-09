#ifndef _ASM_X86_ALTERNATIVE_ASM_H_
#define _ASM_X86_ALTERNATIVE_ASM_H_

#ifdef __ASSEMBLY__

/*
 * Issue one struct alt_instr descriptor entry (need to put it into
 * the section .altinstructions, see below). This entry contains
 * enough information for the alternatives patching code to patch an
 * instruction. See apply_alternatives().
 */
.macro altinstruction_entry orig repl feature orig_len repl_len
    .long \orig - .
    .long \repl - .
    .word \feature
    .byte \orig_len
    .byte \repl_len
.endm

#define decl_orig(insn)         .L\@_orig_s:      insn; .L\@_orig_e:
#define orig_len               (.L\@_orig_e       -     .L\@_orig_s)

#define decl_repl(insn, nr)     .L\@_repl_s\()nr: insn; .L\@_repl_e\()nr:
#define repl_len(nr)           (.L\@_repl_e\()nr  -     .L\@_repl_s\()nr)

.macro ALTERNATIVE oldinstr, newinstr, feature
    decl_orig(\oldinstr)

    .pushsection .altinstructions, "a", @progbits
    altinstruction_entry .L\@_orig_s, .L\@_repl_s1, \feature, \
        orig_len, repl_len(1)

    .section .discard, "a", @progbits
    /* Assembler-time check that \newinstr isn't longer than \oldinstr. */
    .byte 0xff + repl_len(1) - orig_len

    .section .altinstr_replacement, "ax", @progbits

    decl_repl(\newinstr, 1)

    .popsection
.endm

.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
    decl_orig(\oldinstr)

    .pushsection .altinstructions, "a", @progbits

    altinstruction_entry .L\@_orig_s, .L\@_repl_s1, \feature1, \
        orig_len, repl_len(1)
    altinstruction_entry .L\@_orig_s, .L\@_repl_s2, \feature2, \
        orig_len, repl_len(2)

    .section .discard, "a", @progbits
    /* Assembler-time check that \newinstr{1,2} aren't longer than \oldinstr. */
    .byte 0xff + repl_len(1) - orig_len
    .byte 0xff + repl_len(2) - orig_len

    .section .altinstr_replacement, "ax", @progbits

    decl_repl(\newinstr1, 1)
    decl_repl(\newinstr2, 2)

    .popsection
.endm

#undef repl_len
#undef decl_repl
#undef orig_len
#undef decl_orig

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
