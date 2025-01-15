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

   * - D4.10
     - Including multiple times a .c file is safe because every function or data item
       it defines would in (the common case) be already defined.
       Peer reviewed by the community.
     - Tagged as `safe` for ECLAIR.

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

   * - R2.1
     - The asm-offset files are not linked deliberately, since they are used to
       generate definitions for asm modules.
     - Tagged as `deliberate` for ECLAIR.

   * - R2.2
     - Proving compliance with respect to Rule 2.2 is generally impossible:
       see `<https://arxiv.org/abs/2212.13933>`_ for details. Moreover, peer
       review gives us confidence that no evidence of errors in the program's
       logic has been missed due to undetected violations of Rule 2.2, if any.
       Testing on time behavior gives us confidence on the fact that, should the
       program contain dead code that is not removed by the compiler, the
       resulting slowdown is negligible.
     - Project-wide deviation, tagged as `disapplied` for ECLAIR.

   * - R2.6
     - Labels deliberately marked as unused trough the pseudo-attribute
       `__maybe_unused` are either the result of them not being in certain build
       configurations, or as a deliberate practice (e.g., `unimplemented_insn`).
       Given that the compiler is then entitled to remove them, the presence of
       such labels poses no risks.
     - Tagged as `deliberate` for ECLAIR.

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

   * - R5.5
     - Macros expanding to their own name are allowed.
     - Tagged as `deliberate` for ECLAIR.

   * - R5.5
     - Clashes between names of function-like macros and identifiers of
       non-callable entities are allowed.
     - Tagged as `deliberate` for ECLAIR.

   * - R5.5
     - Clashes between function names and macros are deliberate for string
       handling functions since some architectures may want to use their own
       arch-specific implementation.
     - Tagged as `deliberate` for ECLAIR.

   * - R5.5
     - In libelf, clashes between macros and function names are deliberate and
       needed to prevent the use of undecorated versions of memcpy, memset and
       memmove.
     - Tagged as `deliberate` for ECLAIR.

   * - R5.6
     - The type ret_t is deliberately defined multiple times depending on the
       type of guest to service.
     - Tagged as `deliberate` for ECLAIR.

   * - R5.6
     - On X86, some types are deliberately defined multiple times, depending on
       the number of guest paging levels.
     - Tagged as `deliberate` for ECLAIR. Such types are:
         - guest_intpte_t
         - guest_l[12]e_t

   * - R5.6
     - Some files are not subject to respect MISRA rules at
       the moment, but, among these out-of-scope files, there are definitions
       of typedef names that are already defined within in-scope files and
       therefore, ECLAIR does report a violation since not all the files
       involved in the violation are excluded from the analysis.
     - Tagged as `deliberate` for ECLAIR. Such excluded files are:
         - xen/include/efi/*
         - xen/arch/*/include/asm/*/efibind.h

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

   * - R8.3
     - Parameter name "unused" (with an optional numeric suffix) is deliberate
       and makes explicit the intention of not using such parameter within the
       function.
     - Tagged as `deliberate` for ECLAIR.

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

   * - R8.4
     - Functions and variables used only by asm modules are marked with
       the `asmlinkage` macro. Existing code may use a SAF-1-safe
       textual deviation (see safe.json), but new code should not use
       it.
     - Tagged as `safe` for ECLAIR.

   * - R8.4
     - Some functions are excluded from non-debug build, therefore the absence
       of declaration is safe.
     - Tagged as `safe` for ECLAIR, such functions are:
         - apei_read_mce()
         - apei_check_mce()
         - apei_clear_mce()

   * - R8.4
     - Given that bsearch and sort are defined with the attribute 'gnu_inline',
       it's deliberate not to have a prior declaration.
       See Section \"6.33.1 Common Function Attributes\" of \"GCC_MANUAL\" for
       a full explanation of gnu_inline.
     - Tagged as `deliberate` for ECLAIR.

   * - R8.4
     - first_valid_mfn is defined in this way because the current lack of NUMA
       support in Arm and PPC requires it.
     - Tagged as `deliberate` for ECLAIR.

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

   * - R11.1
     - The conversion from a function pointer to unsigned long or (void \*) does
       not lose any information, provided that the target type has enough bits
       to store it.
     - Tagged as `safe` for ECLAIR.

   * - R11.1
     - The conversion from a function pointer to a boolean has a well-known
       semantics that do not lead to unexpected behaviour.
     - Tagged as `safe` for ECLAIR.

   * - R11.2
     - The conversion from a pointer to an incomplete type to unsigned long
       does not lose any information, provided that the target type has enough
       bits to store it.
     - Tagged as `safe` for ECLAIR.

   * - R11.3
     - Conversions to object pointers that have a pointee type with a smaller
       (i.e., less strict) alignment requirement are safe.
     - Tagged as `safe` for ECLAIR.

   * - R11.6
     - Conversions from and to integral types are safe, in the assumption that
       the target type has enough bits to store the value.
       See also Section \"4.7 Arrays and Pointers\" of \"GCC_MANUAL\"
     - Tagged as `safe` for ECLAIR.

   * - R11.6
     - The conversion from a pointer to a boolean has a well-known semantics
       that do not lead to unexpected behaviour.
     - Tagged as `safe` for ECLAIR.

   * - R11.8
     - Violations caused by container_of are due to pointer arithmetic operations
       with the provided offset. The resulting pointer is then immediately cast back to its
       original type, which preserves the qualifier. This use is deemed safe.
       Fixing this violation would require to increase code complexity and lower readability.
     - Tagged as `safe` for ECLAIR.

   * - R11.8
     - Violations caused by function __hvm_copy occur when a const void
       argument is passed, as the const qualifier is stripped. However, in such
       cases, the function ensures that it does not modify the buffer
       referenced by the argument, therefore, this use is deemed safe. Fixing
       this violation would require to increase code complexity and lower
       readability.
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

   * - R13.6
     - On x86, macros alternative_v?call[0-9] use sizeof and typeof to check
       that the argument types match the corresponding parameter ones.
     - Tagged as `deliberate` for ECLAIR.

   * - R13.6
     - Anything, no matter how complicated, inside the BUILD_BUG_ON macro is
       subject to a compile-time evaluation without relevant side effects."
     - Tagged as `safe` for ECLAIR.

   * - R14.2
     - The severe restrictions imposed by this rule on the use of 'for'
       statements are not counterbalanced by the presumed facilitation of the
       peer review activity.
     - Project-wide deviation; tagged as `disapplied` for ECLAIR.

   * - R14.3
     - The Xen team relies on the fact that invariant conditions of 'if'
       statements and conditional operators are deliberate.
     - Tagged as `deliberate` for ECLAIR.

   * - R14.3
     - Switches having a 'sizeof' operator as the condition are deliberate and
       have limited scope.
     - Tagged as `deliberate` for ECLAIR.

   * - R14.3
     - The use of an invariant size argument in {put,get}_unsafe_size and
       array_access_ok, as defined in arch/x86(_64)?/include/asm/uaccess.h is
       deliberate and is deemed safe.
     - Tagged as `deliberate` for ECLAIR.

   * - R14.4
     - A controlling expression of 'if' and iteration statements having
       integer, character or pointer type has a semantics that is well-known to
       all Xen developers.
     - Tagged as `deliberate` for ECLAIR.

   * - R14.4
     - The XEN team relies on the fact that the enum is_dying has the
       constant with assigned value 0 act as false and the other ones as true,
       therefore have the same behavior of a boolean.
     - Tagged as `deliberate` for ECLAIR.

   * - R16.2
     - Complying with the Rule would entail a lot of code duplication in the
       implementation of the x86 emulator, therefore it is deemed better to
       leave such files as is.
     - Tagged as `deliberate` for ECLAIR.

   * - R16.3
     - Statements that change the control flow (i.e., break, continue, goto,
       return) and calls to functions that do not return the control back are
       \"allowed terminal statements\".
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - An if-else statement having both branches ending with one of the allowed
       terminal statemets is itself an allowed terminal statements.
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - An if-else statement having an always true condition and the true
       branch ending with an allowed terminal statement is itself an allowed
       terminal statement.
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - A switch clause ending with a statement expression which, in turn, ends
       with an allowed terminal statement (e.g., the expansion of
       generate_exception()) is safe.
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - A switch clause ending with a do-while-false the body of which, in turn,
       ends with an allowed terminal statement (e.g., PARSE_ERR_RET()) is safe.
       An exception to that is the macro ASSERT_UNREACHABLE() which is
       effective in debug build only: a switch clause ending with
       ASSERT_UNREACHABLE() is not considered safe.
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - Switch clauses ending with pseudo-keyword \"fallthrough\" are safe.
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - Switch clauses ending with failure method \"BUG()\" are safe.
     - Tagged as `safe` for ECLAIR.

   * - R16.3
     - Existing switch clauses not ending with the break statement are safe if
       an explicit comment indicating the fallthrough intention is present.
       However, the use of such comments in new code is deprecated:
       the pseudo-keyword "fallthrough" shall be used.
     - Tagged as `safe` for ECLAIR. The accepted comments are:
         - /\* fall through \*/
         - /\* fall through. \*/
         - /\* fallthrough \*/
         - /\* fallthrough. \*/
         - /\* Fall through \*/
         - /\* Fall through. \*/
         - /\* Fallthrough \*/
         - /\* Fallthrough. \*/

   * - R16.4
     - Switch statements having a controlling expression of enum type
       deliberately do not have a default case: gcc -Wall enables -Wswitch
       which warns (and breaks the build as we use -Werror) if one of the enum
       labels is missing from the switch.
     - Tagged as `deliberate` for ECLAIR.

   * - R16.4
     - A switch statement with a single switch clause and no default label may
       be used in place of an equivalent if statement if it is considered to
       improve readability.
     - Tagged as `deliberate` for ECLAIR.

   * - R16.6
     - A switch statement with a single switch clause and no default label may
       be used in place of an equivalent if statement if it is considered to
       improve readability.
     - Tagged as `deliberate` for ECLAIR.

   * - R17.1
     - printf()-like functions  are allowed to use the variadic features provided
       by `stdarg.h`.
     - Tagged as `deliberate` for ECLAIR.

   * - R17.7
     - Not using the return value of a function does not endanger safety if it
       coincides with an actual argument.
     - Tagged as `safe` for ECLAIR. Such functions are:
         - __builtin_memcpy()
         - __builtin_memmove()
         - __builtin_memset()
         - cpumask_check()

   * - R18.2
     - Subtractions between pointers where at least one of the operand is a
       pointer to a symbol defined by the linker are safe.
     - Tagged as `safe` for ECLAIR.

   * - R18.2
     - Subtraction between pointers encapsulated by macro page_to_mfn
       are safe.
     - Tagged as `safe` for ECLAIR.

   * - R20.4
     - The override of the keyword \"inline\" in xen/compiler.h is present so
       that section contents checks pass when the compiler chooses not to
       inline a particular function.
     - Comment-based deviation.

   * - R20.7
     - Code violating Rule 20.7 is safe when macro parameters are used:
       (1) as function arguments;
       (2) as macro arguments;
       (3) as array indices;
       (4) as lhs in assignments;
       (5) as initializers, possibly designated, in initalizer lists;
       (6) as constant expressions of switch case labels.
     - Tagged as `safe` for ECLAIR.

   * - R20.7
     - Violations due to the use of macros defined in files that are not
       in scope for compliance are allowed, as that is imported code.
     - Tagged as `safe` for ECLAIR.

   * - R20.7
     - To avoid compromising readability, the macros `alternative_(v)?call[0-9]`
       are allowed not to parenthesize their arguments, as there are already
       sanity checks in place.
     - Tagged as `safe` for ECLAIR.

   * - R20.7
     - The macro `count_args_` is not compliant with the rule, but is not likely
       to incur in the risk of being misused or lead to developer confusion, and
       refactoring it to add parentheses breaks its functionality.
     - Tagged as `safe` for ECLAIR.

   * - R20.7
     - The macros `{COMPILE,RUNTIME}_CHECK` defined in
       `xen/include/xen/self-tests.h` are allowed not to parenthesize the "fn"
       argument, to allow function-like macros to be tested as well as
       functions. Given the specialized use of these macros and their limited
       usage scope, omitting parentheses is deemed unlikely to cause issues.
     - Tagged as `deliberate` for ECLAIR.

   * - R20.7
     - Problems related to operator precedence can not occur if the expansion
       of the macro argument is surrounded by tokens '{', '}' and ';'.
     - Tagged as `safe` for ECLAIR.

   * - R20.12
     - Variadic macros that use token pasting often employ the gcc extension
       `ext_paste_comma`, as detailed in `C-language-toolchain.rst`, which is
       not easily replaceable; macros that in addition perform regular argument
       expansion on the same argument subject to the # or ## operators violate
       the Rule if the argument is a macro. 
     - Tagged as `deliberate` for ECLAIR.

   * - R20.12
     - Macros that are used for runtime or build-time assertions contain
       deliberate uses of an argument as both a regular argument and a
       stringification token, to provide useful diagnostic messages.
     - Tagged as `deliberate` for ECLAIR.

   * - R20.12
     - GENERATE_CASE is a local helper macro that allows some selected switch
       statements to be more compact and readable. As such, the risk of
       developer confusion in using such macro is deemed negligible. This
       construct is deviated only in Translation Units that present a violation
       of the Rule due to uses of this macro.
     - Tagged as `deliberate` for ECLAIR.
     
   * - R21.9
     - Xen does not use the `bsearch` and `qsort` functions provided by the C
       Standard Library, but provides in source form its own implementation,
       therefore any unspecified or undefined behavior associated to the
       functions provided by the Standard Library does not apply. Any such
       behavior that may exist in such functions is therefore under the
       jurisdiction of other MISRA C rules.
     - Project-wide deviation, tagged as `deliberate` for ECLAIR.

   * - R21.10
     - Xen does not use the facilities provided by the `\<time.h\>` provided by the C
       Standard Library, but provides in source form its own implementation,
       therefore any unspecified, undefined or implementation-defined behavior
       associated to the functions provided by the Standard Library does not
       apply. Any such behavior that may exist in such functions is therefore
       under the jurisdiction of other MISRA C rules.
     - Project-wide deviation, tagged as `deliberate` for ECLAIR.

Other deviations:
-----------------

.. list-table::
   :header-rows: 1

   * - Deviation
     - Justification

   * - do-while-0 and do-while-1 loops
     - The do-while-0 and do-while-1 loops are well-recognized loop idioms used
       by the Xen community and can therefore be used, even though they would
       cause a number of violations in some instances.

   * - while-0 and while-1 loops
     - while-0 and while-1 are well-recognized loop idioms used by the Xen
       community and can therefore be used, even though they would cause a
       number of violations in some instances.
