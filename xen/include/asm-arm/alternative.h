#ifndef __ASM_ALTERNATIVE_H
#define __ASM_ALTERNATIVE_H

#include <asm/cpufeature.h>

#define ARM_CB_PATCH ARM_NCAPS

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <xen/stringify.h>

struct alt_instr {
	s32 orig_offset;	/* offset to original instruction */
	s32 alt_offset;		/* offset to replacement instruction */
	u16 cpufeature;		/* cpufeature bit set for replacement */
	u8  orig_len;		/* size of original instruction(s) */
	u8  alt_len;		/* size of new instruction(s), <= orig_len */
};

/* Xen: helpers used by common code. */
#define __ALT_PTR(a,f)		((void *)&(a)->f + (a)->f)
#define ALT_ORIG_PTR(a)		__ALT_PTR(a, orig_offset)
#define ALT_REPL_PTR(a)		__ALT_PTR(a, alt_offset)

typedef void (*alternative_cb_t)(const struct alt_instr *alt,
				 const uint32_t *origptr, uint32_t *updptr,
				 int nr_inst);

void apply_alternatives_all(void);
int apply_alternatives(const struct alt_instr *start, const struct alt_instr *end);

#define ALTINSTR_ENTRY(feature, cb)					      \
	" .word 661b - .\n"				/* label           */ \
	" .if " __stringify(cb) " == 0\n"				      \
	" .word 663f - .\n"				/* new instruction */ \
	" .else\n"							      \
	" .word " __stringify(cb) "- .\n"		/* callback */	      \
	" .endif\n"							      \
	" .hword " __stringify(feature) "\n"		/* feature bit     */ \
	" .byte 662b-661b\n"				/* source len      */ \
	" .byte 664f-663f\n"				/* replacement len */

/*
 * alternative assembly primitive:
 *
 * If any of these .org directive fail, it means that insn1 and insn2
 * don't have the same length. This used to be written as
 *
 * .if ((664b-663b) != (662b-661b))
 * 	.error "Alternatives instruction length mismatch"
 * .endif
 *
 * but most assemblers die if insn1 or insn2 have a .inst. This should
 * be fixed in a binutils release posterior to 2.25.51.0.2 (anything
 * containing commit 4e4d08cf7399b606 or c1baaddf8861).
 *
 * Alternatives with callbacks do not generate replacement instructions.
 */
#define __ALTERNATIVE_CFG(oldinstr, newinstr, feature, cfg_enabled, cb)	\
	".if "__stringify(cfg_enabled)" == 1\n"				\
	"661:\n\t"							\
	oldinstr "\n"							\
	"662:\n"							\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(feature,cb)					\
	".popsection\n"							\
	" .if " __stringify(cb) " == 0\n"				\
	".pushsection .altinstr_replacement, \"a\"\n"			\
	"663:\n\t"							\
	newinstr "\n"							\
	"664:\n\t"							\
	".popsection\n\t"						\
	".org	. - (664b-663b) + (662b-661b)\n\t"			\
	".org	. - (662b-661b) + (664b-663b)\n"			\
	".else\n\t"							\
	"663:\n\t"							\
	"664:\n\t"							\
	".endif\n"							\
	".endif\n"

#define _ALTERNATIVE_CFG(oldinstr, newinstr, feature, cfg, ...)	\
	__ALTERNATIVE_CFG(oldinstr, newinstr, feature, IS_ENABLED(cfg), 0)

#define ALTERNATIVE_CB(oldinstr, cb) \
	__ALTERNATIVE_CFG(oldinstr, "NOT_AN_INSTRUCTION", ARM_CB_PATCH, 1, cb)
#else

#include <asm/asm_defns.h>

.macro altinstruction_entry orig_offset alt_offset feature orig_len alt_len
	.word \orig_offset - .
	.word \alt_offset - .
	.hword \feature
	.byte \orig_len
	.byte \alt_len
.endm

.macro alternative_insn insn1, insn2, cap, enable = 1
	.if \enable
661:	\insn1
662:	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663f, \cap, 662b-661b, 664f-663f
	.popsection
	.pushsection .altinstr_replacement, "ax"
663:	\insn2
664:	.popsection
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
	.endif
.endm

/*
 * Begin an alternative code sequence.
 *
 * The code that follows this macro will be assembled and linked as
 * normal. There are no restrictions on this code.
 */
.macro alternative_if_not cap
	.pushsection .altinstructions, "a"
	altinstruction_entry 661f, 663f, \cap, 662f-661f, 664f-663f
	.popsection
661:
.endm

/*
 * Provide the alternative code sequence.
 *
 * The code that follows this macro is assembled into a special
 * section to be used for dynamic patching. Code that follows this
 * macro must:
 *
 * 1. Be exactly the same length (in bytes) as the default code
 *    sequence.
 *
 * 2. Not contain a branch target that is used outside of the
 *    alternative sequence it is defined in (branches into an
 *    alternative sequence are not fixed up).
 */
.macro alternative_else
662:	.pushsection .altinstr_replacement, "ax"
663:
.endm

.macro alternative_cb cb
	.set .Lasm_alt_mode, 0
	.pushsection .altinstructions, "a"
	altinstruction_entry 661f, \cb, ARM_CB_PATCH, 662f-661f, 0
	.popsection
661:
.endm

/*
 * Complete an alternative code sequence.
 */
.macro alternative_endif
664:	.popsection
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
.endm

/*
 * Callback-based alternative epilogue
 */
.macro alternative_cb_end
662:
.endm

#define _ALTERNATIVE_CFG(insn1, insn2, cap, cfg, ...)	\
	alternative_insn insn1, insn2, cap, IS_ENABLED(cfg)

#endif  /*  __ASSEMBLY__  */

/*
 * Usage: asm(ALTERNATIVE(oldinstr, newinstr, feature));
 *
 * Usage: asm(ALTERNATIVE(oldinstr, newinstr, feature, CONFIG_FOO));
 * N.B. If CONFIG_FOO is specified, but not selected, the whole block
 *      will be omitted, including oldinstr.
 */
#define ALTERNATIVE(oldinstr, newinstr, ...)   \
	_ALTERNATIVE_CFG(oldinstr, newinstr, __VA_ARGS__, 1)

#endif /* __ASM_ALTERNATIVE_H */
