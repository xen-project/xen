.. SPDX-License-Identifier: CC-BY-4.0

MISRA C rules for Xen
=====================

.. note::

   **IMPORTANT** All MISRA C rules, text, and examples are copyrighted
   by the MISRA Consortium Limited and used with permission.

   Please refer to https://www.misra.org.uk/ to obtain a copy of MISRA
   C, or for licensing options for other use of the rules.

The following is the list of MISRA C rules that apply to the Xen
hypervisor.

It is possible that in specific circumstances it is best not to follow a
rule because it is not possible or because the alternative leads to
better code quality. Those cases are called "deviations". They are
permissible as long as they are documented. For details, please refer to
docs/misra/documenting-violations.rst and docs/misra/deviations.rst

Other documentation mechanisms are work-in-progress.

The existing codebase is not 100% compliant with the rules. Some of the
violations are meant to be documented as deviations, while some others
should be fixed. Both compliance and documenting deviations on the
existing codebase are work-in-progress.

The list below might need to be updated over time. Reach out to THE REST
maintainers if you want to suggest a change.

.. list-table::
   :header-rows: 1

   * - Dir number
     - Severity
     - Summary
     - Notes

   * - `Dir 1.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_01_01.c>`_
     - Required
     - Any implementation-defined behaviour on which the output of the
       program depends shall be documented and understood
     -

   * - `Dir 2.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_02_01.c>`_
     - Required
     - All source files shall compile without any compilation errors
     -

   * - `Dir 4.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_01.c>`_
     - Required
     - Run-time failures shall be minimized
     - The strategies adopted by Xen to prevent certain classes of runtime
       failures is documented by
       `C-runtime-failures.rst <docs/misra/C-runtime-failures.rst>`_

   * - `Dir 4.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_07.c>`_
     - Required
     - If a function returns error information then that error
       information shall be tested
     -

   * - `Dir 4.10 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_10.c>`_
     - Required
     - Precautions shall be taken in order to prevent the contents of a
       header file being included more than once
     - Files that are intended to be included more than once do not need to
       conform to the directive

   * - `Dir 4.11 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_11.c>`_
     - Required
     - The validity of values passed to library functions shall be checked
     - We do not have libraries in Xen (libfdt and others are not
       considered libraries from MISRA C point of view as they are
       imported in source form)

   * - `Dir 4.14 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_14.c>`_
     - Required
     - The validity of values received from external sources shall be
       checked
     -

.. list-table::
   :header-rows: 1

   * - Rule number
     - Severity
     - Summary
     - Notes

   * - `Rule 1.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_01_01.c>`_
     - Required
     - The program shall contain no violations of the standard C syntax
       and constraints, and shall not exceed the implementation's
       translation limits
     - We make use of several compiler extensions as documented by
       `C-language-toolchain.rst <docs/misra/C-language-toolchain.rst>`_

   * - `Rule 1.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_01_03.c>`_
     - Required
     - There shall be no occurrence of undefined or critical unspecified
       behaviour
     -

   * - `Rule 1.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/>`_
     - Required
     - Emergent language features shall not be used
     - Emergent language features, such as C11 features, should not be
       confused with similar compiler extensions, which we use. When the
       time comes to adopt C11, this rule will be revisited.

   * - `Rule 2.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_02_01_1.c>`_
     - Required
     - A project shall not contain unreachable code
     - The following are allowed:
         - Invariantly constant conditions, e.g. if(IS_ENABLED(CONFIG_HVM)) { S; }
         - Switch with a controlling value statically determined not to
           match one or more case statements
         - Functions that are intended to be referenced only from
           assembly code (e.g. 'do_trap_fiq')
         - asm-offsets.c, as they are not linked deliberately, because
           they are used to generate definitions for asm modules
         - Declarations without initializer are safe, as they are not
           executed

   * - `Rule 2.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_02_06.c>`_
     - Advisory
     - A function should not contain unused label declarations
     -

   * - `Rule 3.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_03_01.c>`_
     - Required
     - The character sequences /* and // shall not be used within a
       comment
     - Comments containing hyperlinks inside C-style block comments are safe

   * - `Rule 3.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_03_02.c>`_
     - Required
     - Line-splicing shall not be used in // comments
     -

   * - `Rule 4.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_04_01.c>`_
     - Required
     - Octal and hexadecimal escape sequences shall be terminated
     -

   * - `Rule 4.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_04_02.c>`_
     - Advisory
     - Trigraphs should not be used
     -

   * - `Rule 5.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_01_2.c>`_
     - Required
     - External identifiers shall be distinct
     - The Xen characters limit for identifiers is 63. Public headers
       (xen/include/public/) are allowed to retain longer identifiers
       for backward compatibility.

   * - `Rule 5.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_02.c>`_
     - Required
     - Identifiers declared in the same scope and name space shall be
       distinct
     - The Xen characters limit for identifiers is 63. Public headers
       (xen/include/public/) are allowed to retain longer identifiers
       for backward compatibility.

   * - `Rule 5.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_03.c>`_
     - Required
     - An identifier declared in an inner scope shall not hide an
       identifier declared in an outer scope
     - Using macros as macro parameters at invocation time is allowed
       even if both macros use identically named local variables, e.g.
       max(var0, min(var1, var2))

   * - `Rule 5.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_04.c>`_
     - Required
     - Macro identifiers shall be distinct
     - The Xen characters limit for macro identifiers is 63. Public
       headers (xen/include/public/) are allowed to retain longer
       identifiers for backward compatibility.

   * - `Rule 5.5 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_05.c>`_
     - Required
     - Identifiers shall be distinct from macro names
     - Macros expanding to their own name are allowed, e.g.::

           #define x x

       Clashes between names of function-like macros and identifiers of
       non-callable entities are allowed. Callable entities having an
       identifier that is the same of the name of a
       function-like macro are not allowed. Example (not allowed)::

           #define f(x, y) f(x, y)
           void f(int x, int y);

   * - `Rule 5.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_06.c>`_
     - Required
     - A typedef name shall be a unique identifier
     -

   * - `Rule 6.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_06_01.c>`_
     - Required
     - Bit-fields shall only be declared with an appropriate type
     - In addition to the C99 types, we also consider appropriate types
       enum and all explicitly signed / unsigned integer types.

   * - `Rule 6.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_06_02.c>`_
     - Required
     - Single-bit named bit fields shall not be of a signed type
     -

   * - `Rule 7.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_07_01.c>`_
     - Required
     - Octal constants shall not be used
     -

   * - `Rule 7.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_07_02.c>`_
     - Required
     - A "u" or "U" suffix shall be applied to all integer constants
       that are represented in an unsigned type
     - The rule asks that any integer literal that is implicitly
       unsigned is made explicitly unsigned by using one of the
       indicated suffixes.  As an example, on a machine where the int
       type is 32-bit wide, 0x77777777 is signed whereas 0x80000000 is
       (implicitly) unsigned. In order to comply with the rule, the
       latter should be rewritten as either 0x80000000u or 0x80000000U.
       Consistency considerations may suggest using the same suffix even
       when not required by the rule. For instance, if one has:

       Original: f(0x77777777); f(0x80000000);

       one should do

       Solution 1: f(0x77777777U); f(0x80000000U);

       over

       Solution 2: f(0x77777777); f(0x80000000U);

       after having ascertained that "Solution 1" is compatible with the
       intended semantics.

   * - `Rule 7.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_07_03.c>`_
     - Required
     - The lowercase character l shall not be used in a literal suffix
     -

   * - `Rule 7.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_07_04.c>`_
     - Required
     - A string literal shall not be assigned to an object unless the
       object type is pointer to const-qualified char
     - All "character types" are permitted, as long as the string
       element type and the character type match. (There should be no
       casts.) Assigning a string literal to any object with type
       "pointer to const-qualified void" is allowed.

   * - `Rule 8.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_01.c>`_
     - Required
     - Types shall be explicitly specified
     -

   * - `Rule 8.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_02.c>`_
     - Required
     - Function types shall be in prototype form with named parameters
     - Clarification: both function and function pointers types shall
       have named parameters.

   * - `Rule 8.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_03.c>`_
     - Required
     - All declarations of an object or function shall use the same
       names and type qualifiers
     - The type ret_t maybe be deliberately used and defined as int or
       long depending on the type of guest to service

   * - `Rule 8.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_04.c>`_
     - Required
     - A compatible declaration shall be visible when an object or
       function with external linkage is defined
     - Allowed exceptions: asm-offsets.c, definitions for asm modules
       not called from C code, gcov_base.c

   * - `Rule 8.5 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_05_2.c>`_
     - Required
     - An external object or function shall be declared once in one and only one file
     -

   * - `Rule 8.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_06_2.c>`_
     - Required
     - An identifier with external linkage shall have exactly one
       external definition
     - Declarations without definitions are allowed (specifically when
       the definition is compiled-out or optimized-out by the compiler)

   * - `Rule 8.8 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_08.c>`_
     - Required
     - The static storage class specifier shall be used in all
       declarations of objects and functions that have internal linkage
     -

   * - `Rule 8.10 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_10.c>`_
     - Required
     - An inline function shall be declared with the static storage class
     - gnu_inline (without static) is allowed.

   * - `Rule 8.12 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_12.c>`_
     - Required
     - Within an enumerator list the value of an implicitly-specified
       enumeration constant shall be unique
     -

   * - `Rule 8.14 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_14.c>`_
     - Required
     - The restrict type qualifier shall not be used
     -

   * - `Rule 9.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_09_01.c>`_
     - Mandatory
     - The value of an object with automatic storage duration shall not
       be read before it has been set
     - Rule clarification: do not use variables before they are
       initialized. An explicit initializer is not necessarily required.
       Try reducing the scope of the variable. If an explicit
       initializer is added, consider initializing the variable to a
       poison value.

   * - `Rule 9.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_09_02.c>`_
     - Required
     - The initializer for an aggregate or union shall be enclosed in
       braces
     -

   * - `Rule 9.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_09_03.c>`_
     - Required
     - Arrays shall not be partially initialized
     - {} is also allowed to specify explicit zero-initialization

   * - `Rule 9.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_09_04.c>`_
     - Required
     - An element of an object shall not be initialized more than once
     -

   * - `Rule 10.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_10_01.c>`_
     - Required
     - Operands shall not be of an inappropriate essential type
     - The following are allowed:
         - Value-preserving conversions of integer constants
         - Bitwise and, or, xor, one's complement, bitwise and assignment,
           bitwise or assignment, bitwise xor assignment (bitwise and, or, xor
           are safe on non-negative integers; also Xen assumes two's complement
           representation)
         - Left shift, right shift, left shift assignment, right shift
           assignment (see C-language-toolchain.rst for uses of
           compilers' extensions)
         - Implicit conversions to boolean for conditionals (?: if while
           for) and logical operators (! || &&)
         - The essential type model allows the constants defined by anonymous
           enums (e.g., enum { A, B, C }) to be used as operands to arithmetic
           operators, as they have a signed essential type.

   * - `Rule 10.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_10_02.c>`_
     - Required
     - Expressions of essentially character type shall not be used
       inappropriately in addition and subtraction operations
     -

   * - `Rule 10.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_10_03.c>`_
     - Required
     - The value of an expression shall not be assigned to an object
       with a narrower essential type or of a different essential type
       category
     - Please beware that this rule has many violations in the Xen
       codebase today, and its adoption is aspirational. However, when
       submitting new patches please try to decrease the number of
       violations when possible.

       gcc has a helpful warning that can help you spot and remove
       violations of this kind: conversion. For instance, you can use
       it as follows:

       CFLAGS="-Wconversion -Wno-error=sign-conversion -Wno-error=conversion" make -C xen

   * - `Rule 10.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_10_04.c>`_
     - Required
     - Both operands of an operator in which the usual arithmetic
       conversions are performed shall have the same essential type
       category
     - Please beware that this rule has many violations in the Xen
       codebase today, and its adoption is aspirational. However, when
       submitting new patches please try to decrease the number of
       violations when possible.

       gcc has a helpful warning that can help you spot and remove
       violations of this kind: arith-conversion. For instance, you
       can use it as follows:

       CFLAGS="-Warith-conversion -Wno-error=arith-conversion" make -C xen

   * - `Rule 11.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_01.c>`_
     - Required
     - Conversions shall not be performed between a pointer to a
       function and any other type
     - All conversions to integer types are permitted if the destination
       type has enough bits to hold the entire value. Conversions to
       bool and void* are permitted.

   * - `Rule 11.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_02.c>`_
     - Required
     - Conversions shall not be performed between a pointer to an
       incomplete type and any other type
     - All conversions to integer types are permitted if the destination
       type has enough bits to hold the entire value. Conversions to
       bool and void* are permitted.

   * - `Rule 11.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_03.c>`_
     - Required
     - A cast shall not be performed between a pointer to object type
       and a pointer to a different object type
     -

   * - `Rule 11.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_06.c>`_
     - Required
     - A cast shall not be performed between pointer to void and an
       arithmetic type
     - All conversions to integer types are permitted if the destination
       type has enough bits to hold the entire value. Conversions to
       bool are permitted.

   * - `Rule 11.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_07.c>`_
     - Required
     - A cast shall not be performed between pointer to object and a noninteger arithmetic type
     -

   * - `Rule 11.8 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_08.c>`_
     - Required
     - A cast shall not remove any const or volatile qualification from the type pointed to by a pointer
     -

   * - `Rule 11.9 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_11_09.c>`_
     - Required
     - The macro NULL shall be the only permitted form of null pointer constant
     -

   * - `Rule 12.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_12_02.c>`_
     - Required
     - The right hand operand of a shift operator shall lie in the range
       zero to one less than the width in bits of the essential type of
       the left hand operand
     - We rely on gcc -fsanitize=undefined to check for dangerious
       violations to this rule and to ensure compliance

   * - `Rule 12.5 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_12_05.c>`_
     - Mandatory
     - The sizeof operator shall not have an operand which is a function
       parameter declared as "array of type"
     -

   * - `Rule 13.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_13_01_1.c>`_
     - Required
     - Initializer lists shall not contain persistent side effects
     -

   * - `Rule 13.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_13_02.c>`_
     - Required
     - The value of an expression and its persistent side-effects shall
       be the same under all permitted evaluation orders
     - Be aware that the static analysis tool Eclair might report
       several findings for Rule 13.2 of type "caution". These are
       instances where Eclair is unable to verify that the code is valid
       in regard to Rule 13.2. Caution reports might not be violations.
       The rule should be followed in any case in new code submitted.

   * - `Rule 13.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_13_06.c>`_
     - Required
     - The operand of the sizeof operator shall not contain any
       expression which has potential side effects
     - In addition to sizeof, we also want to apply the rule to typeof
       and alignof

   * - `Rule 14.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_14_01.c>`_
     - Required
     - A loop counter shall not have essentially floating type
     -

   * - `Rule 14.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_14_03.c>`_
     - Required
     - Controlling expressions shall not be invariant
     - Due to the extensive usage of IS_ENABLED, sizeof compile-time
       checks, and other constructs that are detected as errors by MISRA
       C scanners, managing the configuration of a MISRA C scanner for
       this rule would be unmanageable. Thus, this rule is adopted with
       a project-wide deviation on if, ?:, switch(sizeof(...)), and
       switch(offsetof(...)) statements.

       while(0) and while(1) and alike are allowed.

   * - `Rule 14.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_14_04.c>`_
     - Required
     - The controlling expression of an if-statement and the controlling
       expression of an iteration-statement shall have essentially
       Boolean type
     - Automatic conversions of integer types to bool are permitted.
       Automatic conversions of pointer types to bool are permitted.
       This rule still applies to enum types.

   * - `Rule 16.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_16_03.c>`_
     - Required
     - An unconditional break statement shall terminate every switch-clause_
     - In addition to break, also other unconditional flow control statements
       such as continue, return, goto are allowed.

   * - `Rule 16.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_16_04.c>`_
     - Required
     - Every switch statement shall have a default label
     - Switch statements with enums as controlling expression don't need
       a default label as gcc -Wall enables -Wswitch which warns (and
       breaks the build as we use -Werror) if one of the enum labels is
       missing from the switch.

       Switch statements with integer types as controlling expression
       should have a default label:

       - if the switch is expected to handle all possible cases
         explicitly, then a default label shall be added to handle
         unexpected error conditions, using BUG(), ASSERT(), WARN(),
         domain_crash(), or other appropriate methods;

       - if the switch is expected to handle a subset of all possible
         cases, then an empty default label shall be added with an
         in-code comment on top of the default label with a reason and
         when possible a more detailed explanation. Example::

             default:
                 /* Notifier pattern */
                 break;

   * - `Rule 16.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_16_02.c>`_
     - Required
     - A switch label shall only be used when the most closely-enclosing
       compound statement is the body of a switch statement
     - The x86 emulator (xen/arch/x86/x86_emulate*) is exempt from
       compliance with this rule. Efforts to make the x86 emulator
       adhere to Rule 16.2 would result in increased complexity and
       maintenance difficulty, and could potentially introduce bugs. 

   * - `Rule 16.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_16_06.c>`_
     - Required
     - Every switch statement shall have at least two switch-clauses
     - Single-clause switches are allowed when they do not involve a
       default label.

   * - `Rule 16.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_16_07.c>`_
     - Required
     - A switch-expression shall not have essentially Boolean type
     -

   * - `Rule 17.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_01.c>`_
     - Required
     - The features of <stdarg.h> shall not be used
     -

   * - `Rule 17.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_02.c>`_
     - Required
     - Functions shall not call themselves, either directly or indirectly
     - Limited forms of recursion are allowed if the recursion is bound
       (there is an upper limit and the upper limit is enforced.) The
       bounding should be explained in a comment or in a deviation.

   * - `Rule 17.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_03.c>`_
     - Mandatory
     - A function shall not be declared implicitly
     -

   * - `Rule 17.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_04.c>`_
     - Mandatory
     - All exit paths from a function with non-void return type shall
       have an explicit return statement with an expression
     -

   * - `Rule 17.5 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_05.c>`_
     - Advisory
     - The function argument corresponding to a parameter declared to
       have an array type shall have an appropriate number of elements
     -

   * - `Rule 17.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_06.c>`_
     - Mandatory
     - The declaration of an array parameter shall not contain the
       static keyword between the [ ]
     -

   * - `Rule 17.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_07.c>`_
     - Required
     - The value returned by a function having non-void return type
       shall be used
     - Please beware that this rule has many violations in the Xen
       codebase today, and its adoption is aspirational. However, when
       submitting new patches please try to decrease the number of
       violations when possible.

   * - `Rule 18.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_18_01.c>`_
     - Required
     - A pointer resulting from arithmetic on a pointer operand shall
       address an element of the same array as that pointer operand
     -

   * - `Rule 18.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_18_02.c>`_
     - Required
     - Subtraction between pointers shall only be applied to pointers
       that address elements of the same array
     - Be aware that the static analysis tool Eclair might report
       several findings for Rule 18.2 of type "caution". These are
       instances where Eclair is unable to verify that the code is valid
       in regard to Rule 18.2. Caution reports might not be violations.
       The rule should be followed in any case in new code submitted.

   * - `Rule 18.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_18_03.c>`_
     - Required
     - The relational operators > >= < and <= shall not be applied to objects of pointer type except where they point into the same object
     -

   * - `Rule 18.8 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_18_08.c>`_
     - Required
     - Variable-length array types shall not be used
     -

   * - `Rule 18.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_18_06_1.c>`_
     - Required
     - The address of an object with automatic storage shall not be
       copied to another object that persists after the first object has
       ceased to exist
     -

   * - `Rule 19.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_19_01.c>`_
     - Mandatory
     - An object shall not be assigned or copied to an overlapping
       object
     - Be aware that the static analysis tool Eclair might report
       several findings for Rule 19.1 of type "caution". These are
       instances where Eclair is unable to verify that the code is valid
       in regard to Rule 19.1. Caution reports are not violations.

   * - `Rule 20.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_02.c>`_
     - Required
     - The ', " or \ characters and the /* or // character sequences
       shall not occur in a header file name
     -

   * - `Rule 20.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_03.c>`_
     - Required
     - The #include directive shall be followed by either a <filename>
       or "filename" sequence
     -

   * - `Rule 20.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_04.c>`_
     - Required
     - A macro shall not be defined with the same name as a keyword
     -

   * - `Rule 20.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_06.c>`_
     - Required
     - Tokens that look like a preprocessing directive shall not occur
       within a macro argument
     -

   * - `Rule 20.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_07.c>`_
     - Required
     - Expressions resulting from the expansion of macro parameters
       shall be enclosed in parentheses
     - Extra parentheses are not required when macro parameters are used
       as function arguments, as macro arguments, array indices, lhs in
       assignments or as initializers in initalizer lists. In addition,
       the use of a named variable argument in a macro that would constitute
       a violation of the rule is allowed by ECLAIR as an extension of the
       MISRA guideline, since it may not always be possible to parenthesize
       such argument and the feature is non-standard::

         #define M(args...) args
         #if M(1) + 0 

   * - `Rule 20.9 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_09.c>`_
     - Required
     - All identifiers used in the controlling expression of #if or
       #elif preprocessing directives shall be #define'd before
       evaluation
     -

   * - `Rule 20.11 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_11.c>`_
     - Required
     - A macro parameter immediately following a # operator shall not
       immediately be followed by a ## operator
     -

   * - `Rule 20.12 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_12.c>`_
     - Required
     - A macro parameter used as an operand to the # or ## operators,
       which is itself subject to further macro replacement, shall only
       be used as an operand to these operators
     - Variadic macros are allowed to violate the rule.

   * - `Rule 20.13 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_13.c>`_
     - Required
     - A line whose first token is # shall be a valid preprocessing
       directive
     -

   * - `Rule 20.14 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_14.c>`_
     - Required
     - All #else #elif and #endif preprocessor directives shall reside
       in the same file as the #if #ifdef or #ifndef directive to which
       they are related
     -

   * - `Rule 21.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_01.c>`_
     - Required
     - #define and #undef shall not be used on a reserved identifier or
       reserved macro name
     - Identifiers starting with an underscore followed by another underscore
       or an upper-case letter are reserved. Today Xen uses many, such as
       header guards and bitwise manipulation functions. Upon analysis it turns
       out Xen identifiers do not clash with the identifiers used by modern
       GCC, but that is not a guarantee that there won't be a naming clash in
       the future or with another compiler.  For these reasons we discourage
       the introduction of new reserved identifiers in Xen, and we see it as
       positive the reduction of reserved identifiers. At the same time,
       certain identifiers starting with two underscores are also commonly used
       in Linux (e.g. __set_bit) and we don't think it would be an improvement
       to rename them.

   * - `Rule 21.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_02.c>`_
     - Required
     - A reserved identifier or reserved macro name shall not be
       declared
     - See comment for Rule 21.1

   * - `Rule 21.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_03.c>`_
     - Required
     - The memory allocation and deallocation functions of <stdlib.h>
       shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_04.c>`_
     - Required
     - The standard header file <setjmp.h> shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.5 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_05.c>`_
     - Required
     - The standard header file <signal.h> shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_06.c>`_
     - Required
     - The Standard Library input/output routines shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_07.c>`_
     - Required
     - The Standard Library functions atof, atoi, atol and atoll of
       <stdlib.h> shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.8 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_08.c>`_
     - Required
     - The Standard Library functions abort, exit and system of
       <stdlib.h> shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.9 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_09.c>`_
     - Required
     - The library functions bsearch and qsort of <stdlib.h> shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.10 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_10.c>`_
     - Required
     - The Standard Library time and date routines shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.11 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_11.c>`_
     - Required
     - The standard header file <tgmath.h> shall not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.12 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_12.c>`_
     - Advisory
     - The exception handling features of <fenv.h> should not be used
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 21.13 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_13.c>`_
     - Mandatory
     - Any value passed to a function in <ctype.h> shall be representable as an
       unsigned char or be the value EOF
     -

   * - `Rule 21.14 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_14.c>`_
     - Required
     - The Standard Library function memcmp shall not be used to compare
       null terminated strings
     -

   * - `Rule 21.15 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_15.c>`_
     - Required
     - The pointer arguments to the Standard Library functions memcpy,
       memmove and memcmp shall be pointers to qualified or unqualified
       versions of compatible types
     -

   * - `Rule 21.16 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_16.c>`_
     - Required
     - The pointer arguments to the Standard Library function memcmp
       shall point to either a pointer type, an essentially signed type,
       an essentially unsigned type, an essentially Boolean type or an
       essentially enum type
     - void* arguments are allowed

   * - `Rule 21.17 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_17.c>`_
     - Mandatory
     - Use of the string handling functions from <string.h> shall not result in
       accesses beyond the bounds of the objects referenced by their pointer
       parameters
     -

   * - `Rule 21.18 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_18.c>`_
     - Mandatory
     - The size_t argument passed to any function in <string.h> shall have an
       appropriate value
     -

   * - `Rule 21.19 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_19.c>`_
     - Mandatory
     - The pointers returned by the Standard Library functions localeconv,
       getenv, setlocale or, strerror shall only be used as if they have
       pointer to const-qualified type
     -

   * - `Rule 21.20 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_21_20.c>`_
     - Mandatory
     - The pointer returned by the Standard Library functions asctime ctime
       gmtime localtime localeconv getenv setlocale or strerror shall not be
       used following a subsequent call to the same function
     -

   * - `Rule 21.21 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/>`_
     - Required
     - The Standard Library function system of <stdlib.h> shall not be used
     -

   * - `Rule 22.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_01.c>`_
     - Required
     - All resources obtained dynamically by means of Standard Library
       functions shall be explicitly released
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 22.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_02.c>`_
     - Mandatory
     - A block of memory shall only be freed if it was allocated by means of a
       Standard Library function
     -

   * - `Rule 22.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_03.c>`_
     - Required
     - The same file shall not be open for read and write access at the
       same time on different streams 
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 22.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_04.c>`_
     - Mandatory
     - There shall be no attempt to write to a stream which has been opened as
       read-only
     -

   * - `Rule 22.5 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_05.c>`_
     - Mandatory
     - A pointer to a FILE object shall not be dereferenced
     -

   * - `Rule 22.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_06.c>`_
     - Mandatory
     - The value of a pointer to a FILE shall not be used after the associated
       stream has been closed
     -

   * - `Rule 22.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_07.c>`_
     - Required
     - The macro EOF shall only be compared with the unmodified return
       value from any Standard Library function capable of returning EOF
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 22.8 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_08.c>`_
     - Required
     - The value of errno shall be set to zero prior to a call to an
       errno-setting-function
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 22.9 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_09.c>`_
     - Required
     - The value of errno shall be tested against zero after calling an
       errno-setting-function
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_

   * - `Rule 22.10 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_22_10.c>`_
     - Required
     - The value of errno shall only be tested when the last function to
       be called was an errno-setting-function
     - Xen doesn't provide, use, or link against a Standard Library [#xen-stdlib]_


Terms & Definitions
-------------------

.. _switch-clause:

A *switch clause* can be defined as:
"the non-empty list of statements which follows a non-empty list of
case/default labels".
A formal definition is available within the amplification of MISRA C:2012
Rule 16.1.

.. rubric:: Footnotes

.. [#xen-stdlib] Xen implements itself a few functions with names that match
   the corresponding function names of the Standard Library for developers'
   convenience. These functions are part of the Xen code and subject to
   analysis.
