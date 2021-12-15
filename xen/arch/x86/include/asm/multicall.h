/******************************************************************************
 * asm-x86/multicall.h
 */

#ifndef __ASM_X86_MULTICALL_H__
#define __ASM_X86_MULTICALL_H__

#include <xen/multicall.h>

typeof(arch_do_multicall_call) pv_do_multicall_call, hvm_do_multicall_call;

#endif /* __ASM_X86_MULTICALL_H__ */
