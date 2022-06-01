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

   * - `Rule 3.2 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_03_02.c>`_
     - Required
     - Line-splicing shall not be used in // comments
     -

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

   * - `Rule 8.12 <https://gitlab.com/MISRA/MISRA-C/MISRA-C-2012/Example-Suite/-/blob/master/R_08_12.c>`_
     - Required
     - Within an enumerator list the value of an implicitly-specified
       enumeration constant shall be unique
     -
