#ifndef __X86_ASM_NOPS_H__
#define __X86_ASM_NOPS_H__

/*
 * Define nops for use with alternative().
 */

#define NOP_DS_PREFIX 0x3e

/*
 * Opteron 64bit nops
 * 1: nop
 * 2: osp nop
 * 3: osp osp nop
 * 4: osp osp osp nop
 */
#define K8_NOP1 0x90
#define K8_NOP2 0x66,K8_NOP1
#define K8_NOP3 0x66,K8_NOP2
#define K8_NOP4 0x66,K8_NOP3
#define K8_NOP5 K8_NOP3,K8_NOP2
#define K8_NOP6 K8_NOP3,K8_NOP3
#define K8_NOP7 K8_NOP4,K8_NOP3
#define K8_NOP8 K8_NOP4,K8_NOP4
#define K8_NOP9 K8_NOP3,K8_NOP3,K8_NOP3

/*
 * P6 nops
 * uses eax dependencies (Intel-recommended choice)
 * 1: nop
 * 2: osp nop
 * 3: nopl (%eax)
 * 4: nopl 0x00(%eax)
 * 5: nopl 0x00(%eax,%eax,1)
 * 6: osp nopl 0x00(%eax,%eax,1)
 * 7: nopl 0x00000000(%eax)
 * 8: nopl 0x00000000(%eax,%eax,1)
 * 9: nopw 0x00000000(%eax,%eax,1)
 *    Note: All the above are assumed to be a single instruction.
 *          There is kernel code that depends on this.
 */
#define P6_NOP1 0x90
#define P6_NOP2 0x66,0x90
#define P6_NOP3 0x0f,0x1f,0x00
#define P6_NOP4 0x0f,0x1f,0x40,0
#define P6_NOP5 0x0f,0x1f,0x44,0x00,0
#define P6_NOP6 0x66,0x0f,0x1f,0x44,0x00,0
#define P6_NOP7 0x0f,0x1f,0x80,0,0,0,0
#define P6_NOP8 0x0f,0x1f,0x84,0x00,0,0,0,0
#define P6_NOP9 0x66,0x0f,0x1f,0x84,0x00,0,0,0,0

#ifdef __ASSEMBLY__
#define _ASM_MK_NOP(x) .byte x
#else
#define _ASM_MK_NOP(x) ".byte " __stringify(x) "\n"
#endif

#define ASM_NOP1 _ASM_MK_NOP(P6_NOP1)
#define ASM_NOP2 _ASM_MK_NOP(P6_NOP2)
#define ASM_NOP3 _ASM_MK_NOP(P6_NOP3)
#define ASM_NOP4 _ASM_MK_NOP(P6_NOP4)
#define ASM_NOP5 _ASM_MK_NOP(P6_NOP5)
#define ASM_NOP6 _ASM_MK_NOP(P6_NOP6)
#define ASM_NOP7 _ASM_MK_NOP(P6_NOP7)
#define ASM_NOP8 _ASM_MK_NOP(P6_NOP8)
#define ASM_NOP9 _ASM_MK_NOP(P6_NOP9)

#define ASM_NOP_MAX 9

#endif /* __X86_ASM_NOPS_H__ */
