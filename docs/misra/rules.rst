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
permissible as long as they are documented as an in-code comment using
the following format::

    /*
     * MISRA_DEV: Rule ID
     * Justification text.
     */

Other documentation mechanisms are work-in-progress.

The existing codebase is not 100% compliant with the rules. Some of the
violations are meant to be documented as deviations, while some others
should be fixed. Both compliance and documenting deviations on the
existing codebase are work-in-progress.

.. list-table::
   :header-rows: 1

   * - Dir number
     - Severity
     - Summary
     - Notes

   * - `Dir 2.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_02_01.c>`_
     - Required
     - All source files shall compile without any compilation errors
     -

   * - `Dir 4.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_07.c>`_
     - Required
     - If a function returns error information then that error
       information shall be tested
     -

   * - `Dir 4.10 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/D_04_10.c>`_
     - Required
     - Precautions shall be taken in order to prevent the contents of a
       header file being included more than once
     -

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

   * - `Rule 1.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_01_03.c>`_
     - Required
     - There shall be no occurrence of undefined or critical unspecified
       behaviour
     -

   * - `Rule 2.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_02_06.c>`_
     - Advisory
     - A function should not contain unused label declarations
     -

   * - `Rule 3.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_03_01.c>`_
     - Required
     - The character sequences /* and // shall not be used within a
       comment
     -

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
     - The Xen characters limit for identifiers is 40. Public headers
       (xen/include/public/) are allowed to retain longer identifiers
       for backward compatibility.

   * - `Rule 5.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_05_02.c>`_
     - Required
     - Identifiers declared in the same scope and name space shall be
       distinct
     - The Xen characters limit for identifiers is 40. Public headers
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
     - The Xen characters limit for macro identifiers is 40. Public
       headers (xen/include/public/) are allowed to retain longer
       identifiers for backward compatibility.

   * - `Rule 6.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_06_02.c>`_
     - Required
     - Single-bit named bit fields shall not be of a signed type
     -

   * - `Rule 8.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_01.c>`_
     - Required
     - Types shall be explicitly specified
     -

   * - `Rule 8.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_04.c>`_
     - Required
     - A compatible declaration shall be visible when an object or
       function with external linkage is defined
     -

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

   * - `Rule 13.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_13_06.c>`_
     - Mandatory
     - The operand of the sizeof operator shall not contain any
       expression which has potential side effects
     -

   * - `Rule 14.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_14_01.c>`_
     - Required
     - A loop counter shall not have essentially floating type
     -

   * - `Rule 16.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_16_07.c>`_
     - Required
     - A switch-expression shall not have essentially Boolean type
     -

   * - `Rule 17.3 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_03.c>`_
     - Mandatory
     - A function shall not be declared implicitly
     -

   * - `Rule 17.4 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_04.c>`_
     - Mandatory
     - All exit paths from a function with non-void return type shall
       have an explicit return statement with an expression
     -

   * - `Rule 17.6 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_17_06.c>`_
     - Mandatory
     - The declaration of an array parameter shall not contain the
       static keyword between the [ ]
     -

   * - `Rule 19.1 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_19_01.c>`_
     - Mandatory
     - An object shall not be assigned or copied to an overlapping
       object
     - Be aware that the static analysis tool Eclair might report
       several findings for Rule 19.1 of type "caution". These are
       instances where Eclair is unable to verify that the code is valid
       in regard to Rule 19.1. Caution reports are not violations.

   * - `Rule 20.7 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_20_07.c>`_
     - Required
     - Expressions resulting from the expansion of macro parameters
       shall be enclosed in parentheses
     -

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
