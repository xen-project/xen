.. SPDX-License-Identifier: CC-BY-4.0

MISRA C deviations for Xen
==========================

The following is the list of MISRA C:2012 deviations for the Xen codebase that
are not covered by a `SAF-x-safe` or `SAF-x-false-positive-<tool>` comment, as
specified in docs/misra/documenting-violations.rst; the lack of
such comments is usually due to the excessive clutter they would bring to the
codebase or the impossibility to express such a deviation (e.g., if it's
composed of several conditions).

Deviations related to MISRA C:2012 Directives:
----------------------------------------------

.. list-table::
   :header-rows: 1

   * - Directive identifier
     - Justification
     - Notes

   * - D4.3
     - Accepted for the ARM64 codebase
     - Tagged as `disapplied` for ECLAIR on any other violation report.

   * - D4.3
     - The inline asm in 'xen/arch/arm/arm64/lib/bitops.c' is tightly coupled
       with the surronding C code that acts as a wrapper, so it has been decided
       not to add an additional encapsulation layer.
     - Tagged as `deliberate` for ECLAIR.

Deviations related to MISRA C:2012 Rules:
-----------------------------------------

.. list-table::
   :header-rows: 1

   * - Rule identifier
     - Justification
     - Notes

   * - R2.1
     - The compiler implementation guarantees that the unreachable code is
       removed. Constant expressions and unreachable branches of if and switch
       statements are expected.
     - Tagged as `safe` for ECLAIR.

   * - R2.1
     - Unreachability caused by calls to the following functions or macros is
       deliberate and there is no risk of code being unexpectedly left out.
     - Tagged as `deliberate` for ECLAIR. Such macros are:
        - BUG
        - assert_failed
        - __builtin_unreachable
        - ASSERT_UNREACHABLE

   * - R2.1
     - Pure declarations, that is, declarations without initializations are not
       executable, and therefore it is safe for them to be unreachable. The most
       notable example of such a pattern being used in the codebase is that of
       a variable declaration that should be available in all the clauses of a
       switch statement.
     - ECLAIR has been configured to ignore those statements.

   * - R2.2
     - Proving compliance with respect to Rule 2.2 is generally impossible:
       see `<https://arxiv.org/abs/2212.13933>`_ for details. Moreover, peer
       review gives us confidence that no evidence of errors in the program's
       logic has been missed due to undetected violations of Rule 2.2, if any.
       Testing on time behavior gives us confidence on the fact that, should the
       program contain dead code that is not removed by the compiler, the
       resulting slowdown is negligible.
     - Project-wide deviation, tagged as `disapplied` for ECLAIR.

   * - R3.1
     - Comments starting with '/\*' and containing hyperlinks are safe as they
       are not instances of commented-out code.
     - Tagged as `safe` for ECLAIR.

   * - R5.3
     - As specified in rules.rst, shadowing due to macros being used as macro
       arguments is allowed, as it's deemed not at risk of causing developer
       confusion.
     - Tagged as `safe` for ECLAIR. So far, the following macros are deviated:
         - READ_SYSREG and WRITE_SYSREG
         - max_{t}? and min_{t}?
         - read_[bwlq] and read_[bwlq]_relaxed
         - per_cpu and this_cpu
         - __emulate_2op and __emulate_2op_nobyte
         - read_debugreg and write_debugreg

   * - R7.1
     - It is safe to use certain octal constants the way they are defined
       in specifications, manuals, and algorithm descriptions. Such places
       are marked safe with a /\* octal-ok \*/ in-code comment.
     - Tagged as `safe` for ECLAIR.

   * - R7.2
     - Violations caused by __HYPERVISOR_VIRT_START are related to the
       particular use of it done in xen_mk_ulong.
     - Tagged as `deliberate` for ECLAIR.

   * - R7.4
     - Allow pointers of non-character type as long as the pointee is
       const-qualified.
     - ECLAIR has been configured to ignore these assignments.

   * - R8.3
     - The type ret_t is deliberately used and defined as int or long depending
       on the architecture.
     - Tagged as `deliberate` for ECLAIR.

   * - R8.3
     - Some files are not subject to respect MISRA rules at
       the moment, but some entity from a file in scope is used; therefore
       ECLAIR does report a violation, since not all the files involved in the
       violation are excluded from the analysis.
     - Tagged as `deliberate` for ECLAIR. Such excluded files are:
         - xen/arch/x86/time.c
         - xen/arch/x86/acpi/cpu_idle.c
         - xen/arch/x86/mpparse.c
         - xen/common/bunzip2.c
         - xen/common/unlz4.c
         - xen/common/unlzma.c
         - xen/common/unlzo.c
         - xen/common/unxz.c
         - xen/common/unzstd.c

   * - R8.4
     - The definitions present in the files 'asm-offsets.c' for any architecture
       are used to generate definitions for asm modules, and are not called by
       C code. Therefore the absence of prior declarations is safe.
     - Tagged as `safe` for ECLAIR.

   * - R8.4
     - The functions defined in the file xen/common/coverage/gcov_base.c are
       meant to be called from gcc-generated code in a non-release build
       configuration. Therefore, the absence of prior declarations is safe.
     - Tagged as `safe` for ECLAIR.

   * - R8.6
     - The following variables are compiled in multiple translation units
       belonging to different executables and therefore are safe.

       - current_stack_pointer
       - bsearch
       - sort
     - Tagged as `safe` for ECLAIR.

   * - R8.6
     - Declarations without definitions are allowed (specifically when the
       definition is compiled-out or optimized-out by the compiler).
     - Tagged as `deliberate` in ECLAIR.

   * - R8.6
     - The search procedure for Unix linkers is well defined, see ld(1) manual:
       "The linker will search an archive only once, at the location where it
       is specified on the command line. If the archive defines a symbol which
       was undefined in some object which appeared before the archive on the
       command line, the linker will include the appropriate file(s) from the
       archive".
       In Xen, thanks to the order in which file names appear in the build
       commands, if arch-specific definitions are present, they get always
       linked in before searching in the lib.a archive resulting from xen/lib.
     - Tagged as `deliberate` for ECLAIR.

   * - R8.10
     - The gnu_inline attribute without static is deliberately allowed.
     - Tagged as `deliberate` for ECLAIR.

   * - R9.5
     - The possibility of committing mistakes by specifying an explicit
       dimension is higher than omitting the dimension, therefore all such
       instances of violations are deviated.
     - Project-wide deviation, tagged as `deliberate` for ECLAIR.

   * - R10.1, R10.3, R10.4
     - The value-preserving conversions of integer constants are safe.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - Shifting non-negative integers to the right is safe.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - Shifting non-negative integers to the left is safe if the result is still
       non-negative.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - Bitwise logical operations on non-negative integers are safe.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - The implicit conversion to Boolean for logical operator arguments is
       well-known to all Xen developers to be a comparison with 0.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - Xen only supports architectures where signed integers are representend
       using two's complement and all the Xen developers are aware of this. For
       this reason, bitwise operations are safe.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - Given the assumptions on the toolchain detailed in
       docs/misra/C-language-toolchain.rst and the build flags used by the
       project, it is deemed safe to use bitwise shift operators.
       See automation/eclair_analysis/deviations.ecl for the full explanation.
     - Tagged as `safe` for ECLAIR.

   * - R10.1
     - The macro ISOLATE_LSB encapsulates the well-known pattern (x & -x)
       applied to unsigned integer values on 2's complement architectures
       (i.e., all architectures supported by Xen), used to obtain a mask where
       just the least significant nonzero bit of x is set.
       If no bits are set, 0 is returned.
     - Tagged as `safe` for ECLAIR.

   * - R11.9
     - __ACCESS_ONCE uses an integer, which happens to be zero, as a
       compile time check. The typecheck uses a cast. The usage of zero or other
       integers for this purpose is allowed.
     - Tagged as `deliberate` for ECLAIR.

   * - R13.5
     - All developers and reviewers can be safely assumed to be well aware of
       the short-circuit evaluation strategy for logical operators.
     - Project-wide deviation; tagged as `disapplied` for ECLAIR.

   * - R14.2
     - The severe restrictions imposed by this rule on the use of 'for'
       statements are not counterbalanced by the presumed facilitation of the
       peer review activity.
     - Project-wide deviation; tagged as `disapplied` for ECLAIR.

   * - R14.3
     - The Xen team relies on the fact that invariant conditions of 'if'
       statements are deliberate.
     - Project-wide deviation; tagged as `disapplied` for ECLAIR.

   * - R20.7
     - Code violating Rule 20.7 is safe when macro parameters are used:
       (1) as function arguments;
       (2) as macro arguments;
       (3) as array indices;
       (4) as lhs in assignments.
     - Tagged as `safe` for ECLAIR.

Other deviations:
-----------------

.. list-table::
   :header-rows: 1

   * - Deviation
     - Justification

   * - do-while-0 loops
     - The do-while-0 is a well-recognized loop idiom used by the Xen community
       and can therefore be used, even though it would cause a number of
       violations in some instances.

   * - while-0 and while-1 loops
     - while-0 and while-1 are well-recognized loop idioms used by the Xen
       community and can therefore be used, even though they would cause a
       number of violations in some instances.
