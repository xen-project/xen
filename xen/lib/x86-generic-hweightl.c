/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/self-tests.h>

/*
 * An implementation of generic_hweightl() used on hardware without the POPCNT
 * instruction.
 *
 * This function is called from within an ALTERNATIVE in arch_hweightl().
 * i.e. behind the back of the compiler.  Therefore all registers are callee
 * preserved.
 *
 * The ASM is what GCC-12 emits for generic_hweightl() in a release build of
 * Xen, with spilling of %rdi/%rdx to preserve the callers registers.
 *
 * Note: When we can use __attribute__((no_caller_saved_registers))
 *       unconditionally (GCC 7, Clang 5), we can implement this in plain C.
 */
asm (
    ".type arch_generic_hweightl, STT_FUNC\n\t"
    ".globl arch_generic_hweightl\n\t"
    ".hidden arch_generic_hweightl\n\t"
    ".balign " STR(CONFIG_FUNCTION_ALIGNMENT) ", 0x90\n" /* CODE_FILL */
    "arch_generic_hweightl:\n\t"

    "push   %rdi\n\t"
    "push   %rdx\n\t"

    "movabs $0x5555555555555555, %rdx\n\t"
    "mov    %rdi, %rax\n\t"
    "shr    $1, %rax\n\t"
    "and    %rdx, %rax\n\t"
    "sub    %rax, %rdi\n\t"
    "movabs $0x3333333333333333, %rax\n\t"
    "mov    %rdi, %rdx\n\t"
    "shr    $2, %rdi\n\t"
    "and    %rax, %rdx\n\t"
    "and    %rax, %rdi\n\t"
    "add    %rdi, %rdx\n\t"
    "mov    %rdx, %rax\n\t"
    "shr    $4, %rax\n\t"
    "add    %rdx, %rax\n\t"
    "movabs $0x0f0f0f0f0f0f0f0f, %rdx\n\t"
    "and    %rdx, %rax\n\t"
    "movabs $0x0101010101010101, %rdx\n\t"
    "imul   %rdx, %rax\n\t"
    "shr    $" STR(BITS_PER_LONG) "- 8, %rax\n\t"

    "pop    %rdx\n\t"
    "pop    %rdi\n\t"

    "ret\n\t"

    ".size arch_generic_hweightl, . - arch_generic_hweightl\n\t"
);

#ifdef CONFIG_SELF_TESTS
static void __init __constructor test_arch_generic_hweightl(void)
{
    RUNTIME_CHECK(arch_generic_hweightl, 0, 0);
    RUNTIME_CHECK(arch_generic_hweightl, 1, 1);
    RUNTIME_CHECK(arch_generic_hweightl, 3, 2);
    RUNTIME_CHECK(arch_generic_hweightl, 7, 3);
    RUNTIME_CHECK(arch_generic_hweightl, 0xff, 8);

    RUNTIME_CHECK(arch_generic_hweightl, 1 | (1UL << (BITS_PER_LONG - 1)), 2);
    RUNTIME_CHECK(arch_generic_hweightl, -1UL, BITS_PER_LONG);
}
#endif
