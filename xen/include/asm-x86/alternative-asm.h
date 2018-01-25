#ifndef _ASM_X86_ALTERNATIVE_ASM_H_
#define _ASM_X86_ALTERNATIVE_ASM_H_

#ifdef __ASSEMBLY__

/*
 * Issue one struct alt_instr descriptor entry (need to put it into
 * the section .altinstructions, see below). This entry contains
 * enough information for the alternatives patching code to patch an
 * instruction. See apply_alternatives().
 */
.macro altinstruction_entry orig alt feature orig_len alt_len
    .long \orig - .
    .long \alt - .
    .word \feature
    .byte \orig_len
    .byte \alt_len
.endm

.macro ALTERNATIVE oldinstr, newinstr, feature
.Lold_start_\@:
    \oldinstr
.Lold_end_\@:

    .pushsection .altinstructions, "a", @progbits
    altinstruction_entry .Lold_start_\@, .Lnew_start_\@, \feature, \
        (.Lold_end_\@ - .Lold_start_\@), (.Lnew_end_\@ - .Lnew_start_\@)

    .section .discard, "a", @progbits
    /* Assembler-time check that \newinstr isn't longer than \oldinstr. */
    .byte 0xff + (.Lnew_end_\@ - .Lnew_start_\@) - (.Lold_end_\@ - .Lold_start_\@)

    .section .altinstr_replacement, "ax", @progbits
.Lnew_start_\@:
    \newinstr
.Lnew_end_\@:
    .popsection
.endm

.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
.Lold_start_\@:
    \oldinstr
.Lold_end_\@:

    .pushsection .altinstructions, "a", @progbits
    altinstruction_entry .Lold_start_\@, .Lnew1_start_\@, \feature1, \
        (.Lold_end_\@ - .Lold_start_\@), (.Lnew1_end_\@ - .Lnew1_start_\@)
    altinstruction_entry .Lold_start_\@, .Lnew2_start_\@, \feature2, \
        (.Lold_end_\@ - .Lold_start_\@), (.Lnew2_end_\@ - .Lnew2_start_\@)

    .section .discard, "a", @progbits
    /* Assembler-time check that \newinstr{1,2} aren't longer than \oldinstr. */
    .byte 0xff + (.Lnew1_end_\@ - .Lnew1_start_\@) - (.Lold_end_\@ - .Lold_start_\@)
    .byte 0xff + (.Lnew2_end_\@ - .Lnew2_start_\@) - (.Lold_end_\@ - .Lold_start_\@)

    .section .altinstr_replacement, "ax", @progbits
.Lnew1_start_\@:
    \newinstr1
.Lnew1_end_\@:
.Lnew2_start_\@:
    \newinstr2
.Lnew2_end_\@:
    .popsection
.endm

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
