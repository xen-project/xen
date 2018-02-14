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
