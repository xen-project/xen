.. SPDX-License-Identifier: CC-BY-4.0

=============================================
C Dialect and Translation Assumptions for Xen
=============================================

This document specifies the C language dialect used by Xen and
the assumptions Xen makes on the translation toolchain.
It covers, in particular:

1. the used language extensions;
2. the translation limits that the translation toolchains must be able
   to accommodate;
3. the implementation-defined behaviors upon which Xen may depend.

All points are of course relevant for portability.  In addition,
programming in C is impossible without a detailed knowledge of the
implementation-defined behaviors.  For this reason, it is recommended
that Xen developers have familiarity with this document and the
documentation referenced therein.

This document needs maintenance and adaptation in the following
circumstances:

- whenever the compiler is changed or updated;
- whenever the use of a certain language extension is added or removed;
- whenever code modifications cause exceeding the stated translation limits.


Applicable C Language Standard
______________________________

Xen is written in C99 with extensions.  The relevant ISO standard is

    *ISO/IEC 9899:1999/Cor 3:2007*: Programming Languages - C,
    Technical Corrigendum 3.
    ISO/IEC, Geneva, Switzerland, 2007.


Reference Documentation
_______________________

The following documents are referred to in the sequel:

GCC_MANUAL:
  https://gcc.gnu.org/onlinedocs/gcc-12.1.0/gcc.pdf
CPP_MANUAL:
  https://gcc.gnu.org/onlinedocs/gcc-12.1.0/cpp.pdf
ARM64_ABI_MANUAL:
  https://github.com/ARM-software/abi-aa/blob/60a8eb8c55e999d74dac5e368fc9d7e36e38dda4/aapcs64/aapcs64.rst
X86_64_ABI_MANUAL:
  https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build


C Language Extensions
_____________________


The following table lists the extensions currently used in Xen.
The table columns are as follows:

   Extension
      a terse description of the extension;
   Architectures
      a set of Xen architectures making use of the extension;
   References
      when available, references to the documentation explaining
      the syntax and semantics of (each instance of) the extension.


.. list-table::
   :widths: 30 15 55
   :header-rows: 1

   * - Extension
     - Architectures
     - References

   * - Non-standard tokens
     - ARM64, X86_64
     - _Static_assert:
          see Section "2.1 C Language" of GCC_MANUAL.
       asm, __asm__:
          see Sections "6.48 Alternate Keywords" and "6.47 How to Use Inline Assembly Language in C Code" of GCC_MANUAL.
       __volatile__:
          see Sections "6.48 Alternate Keywords" and "6.47.2.1 Volatile" of GCC_MANUAL.
       __const__:
          see Section "6.48 Alternate Keywords" of GCC_MANUAL.
       typeof, __typeof__:
          see Section "6.7 Referring to a Type with typeof" of GCC_MANUAL.
       __alignof__, __alignof:
          see Sections "6.48 Alternate Keywords" and "6.44 Determining the Alignment of Functions, Types or Variables" of GCC_MANUAL.
       __attribute__:
          see Section "6.39 Attribute Syntax" of GCC_MANUAL.
       __builtin_types_compatible_p:
          see Section "6.59 Other Built-in Functions Provided by GCC" of GCC_MANUAL.
       __builtin_va_arg:
          non-documented GCC extension.
       __builtin_offsetof:
          see Section "6.53 Support for offsetof" of GCC_MANUAL.

   * - Empty initialization list
     - ARM64, X86_64
     - Non-documented GCC extension.

   * - Arithmetic operator on pointer to void
     - ARM64, X86_64
     - See Section "6.24 Arithmetic on void- and Function-Pointers" of GCC_MANUAL."

   * - Statements and declarations in expressions
     - ARM64, X86_64
     - See Section "6.1 Statements and Declarations in Expressions" of GCC_MANUAL.

   * - Structure or union definition with no members
     - ARM64, X86_64
     - See Section "6.19 Structures with No Members" of GCC_MANUAL.

   * - Zero size array type
     - ARM64, X86_64
     - See Section "6.18 Arrays of Length Zero" of GCC_MANUAL.

   * - Binary conditional expression
     - ARM64, X86_64
     - See Section "6.8 Conditionals with Omitted Operands" of GCC_MANUAL.

   * - 'Case' label with upper/lower values
     - ARM64, X86_64
     - See Section "6.30 Case Ranges" of GCC_MANUAL.

   * - Unnamed field that is not a bit-field
     - ARM64, X86_64
     - See Section "6.63 Unnamed Structure and Union Fields" of GCC_MANUAL.

   * - Empty declaration
     - ARM64, X86_64
     - Non-documented GCC extension.
       Note: an empty declaration is caused by a semicolon at file scope
       with nothing before it (not to be confused with an empty statement).

   * - Incomplete enum declaration
     - ARM64
     - See Section "6.49 Incomplete enum Types" of GCC_MANUAL.

   * - Implicit conversion from a pointer to an incompatible pointer
     - ARM64, X86_64
     - Non-documented GCC extension.  The documentation for option
       -Wincompatible-pointer-types in Section
       "3.8 Options to Request or Suppress Warnings" of GCC_MANUAL
       is possibly relevant.

   * - Pointer to a function is converted to a pointer to an object or a pointer to an object is converted to a pointer to a function
     - X86_64
     - Non-documented GCC extension.  The information provided in
       https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83584
       is possibly relevant.

   * - Token pasting of ',' and __VA_ARGS__
     - ARM64, X86_64
     - See Section "6.21 Macros with a Variable Number of Arguments" of GCC_MANUAL.

   * - Named variadic macro arguments
     - ARM64, X86_64
     - See Section "6.21 Macros with a Variable Number of Arguments" of GCC_MANUAL.

   * - No arguments for '...' parameter of variadic macro
     - ARM64, X86_64
     - See Section "6.21 Macros with a Variable Number of Arguments" of GCC_MANUAL.

   * - void function returning void expression
     - ARM64, X86_64
     - See the documentation for -Wreturn-type in Section "3.8 Options to Request or Suppress Warnings" of GCC_MANUAL.

   * - GNU statement expressions from macro expansion
     - ARM64, X86_64
     - See Section "6.1 Statements and Declarations in Expressions" of GCC_MANUAL.

   * - Invalid application of sizeof to a void type
     - ARM64, X86_64
     - See Section "6.24 Arithmetic on void- and Function-Pointers" of GCC_MANUAL.

   * - Redeclaration of already-defined enum
     - ARM64, X86_64
     - See Section "6.49 Incomplete enum Types" of GCC_MANUAL.

   * - struct with flexible array member nested in a struct
     - ARM64, X86_64
     - See Section "6.18 Arrays of Length Zero" of GCC_MANUAL.

   * - struct with flexible array member used as an array element
     - ARM64, X86_64
     - See Section "6.18 Arrays of Length Zero" of GCC_MANUAL.

   * - enumerator value outside the range of int
     - ARM64, X86_64
     - Non-documented GCC extension.

   * - Extended integer types
     - X86_64
     - See Section "6.9 128-bit Integers" of GCC_MANUAL.

   * - Designated initializer for a range of elements
     - ARM64, X86_64
     - See Section "6.29 Designated Initializers" of GCC_MANUAL

   * - Signed << compiler-defined behavior
     - All architectures
     - See Section "4.5 Integers" of GCC_MANUAL. As an extension to the
       C language, GCC does not use the latitude given in C99 and C11
       only to treat certain aspects of signed << as undefined.

   * - Signed >> acts on negative numbers by sign extension
     - All architectures
     - See Section "4.5 Integers" of GCC_MANUAL.

Translation Limits
__________________

The following table lists the translation limits that a toolchain has
to satisfy in order to translate Xen.  The numbers given are a
compromise: on the one hand, many modern compilers have very generous
limits (in several cases, the only limitation is the amount of
available memory); on the other hand we prefer setting limits that are
not too high, because compilers do not have any obligation of
diagnosing when a limit has been exceeded, and not too low, so as to
avoid frequently updating this document.  In the table, only the
limits that go beyond the minima specified by the relevant C Standard
are listed.

The table columns are as follows:

   Limit
      a terse description of the translation limit;
   Architectures
      a set relevant of Xen architectures;
   Threshold
      a value that the Xen project does not wish to exceed for that limit
      (this is typically below, often much below what the translation
      toolchain supports);
   References
      when available, references to the documentation providing evidence
      that the translation toolchain honors the threshold (and more).

.. list-table::
   :widths: 30 15 10 45
   :header-rows: 1

   * - Limit
     - Architectures
     - Threshold
     - References

   * - Size of an object
     - ARM64, X86_64
     - 8388608
     - The maximum size of an object is defined in the MAX_SIZE macro, and for a 32 bit architecture is 8MB.
       The maximum size for an array is defined in the PTRDIFF_MAX and in a 32 bit architecture is 2^30-1.
       See occurrences of these macros in GCC_MANUAL.

   * - Characters in one logical source line
     - ARM64
     - 5000
     - See Section "11.2 Implementation limits" of CPP_MANUAL.

   * - Characters in one logical source line
     - X86_64
     - 12000
     - See Section "11.2 Implementation limits" of CPP_MANUAL.

   * - Nesting levels for #include files
     - ARM64
     - 24
     - See Section "11.2 Implementation limits" of CPP_MANUAL.

   * - Nesting levels for #include files
     - X86_64
     - 32
     - See Section "11.2 Implementation limits" of CPP_MANUAL.

   * - case labels for a switch statement (excluding those for any nested switch statements)
     - X86_64
     - 1500
     - See Section "4.12 Statements" of GCC_MANUAL.

   * - Number of significant initial characters in an external identifier
     - ARM64, X86_64
     - 63
     - See Section "4.3 Identifiers" of GCC_MANUAL.


Implementation-Defined Behaviors
________________________________

The following table lists the C language implementation-defined behaviors
relevant for MISRA C:2012 Dir 1.1 upon which Xen may possibly depend.

The table columns are as follows:

   I.-D.B.
      a terse description of the implementation-defined behavior;
   Architectures
      a set relevant of Xen architectures;
   Value(s)
      for i.-d.b.'s with values, the values allowed;
   References
      when available, references to the documentation providing details
      about how the i.-d.b. is resolved by the translation toolchain.

.. list-table::
   :widths: 30 15 10 45
   :header-rows: 1

   * - I.-D.B.
     - Architectures
     - Value(s)
     - References

   * - Allowable bit-field types other than _Bool, signed int, and unsigned int
     - ARM64, X86_64
     - All explicitly signed integer types, all unsigned integer types,
       and enumerations.
     - See Section "4.9 Structures, Unions, Enumerations, and Bit-Fields".

   * - #pragma preprocessing directive that is documented as causing translation failure or some other form of undefined behavior is encountered
     - ARM64, X86_64
     - pack, GCC visibility
     - #pragma pack:
          see Section "6.62.11 Structure-Layout Pragmas" of GCC_MANUAL.
       #pragma GCC visibility:
          see Section "6.62.14 Visibility Pragmas" of GCC_MANUAL.

   * - The number of bits in a byte
     - ARM64
     - 8
     - See Section "4.4 Characters" of GCC_MANUAL and Section "8.1 Data types" of ARM64_ABI_MANUAL.

   * - The number of bits in a byte
     - X86_64
     - 8
     - See Section "4.4 Characters" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - Whether signed integer types are represented using sign and magnitude, two's complement, or one's complement, and whether the extraordinary value is a trap representation or an ordinary value
     - ARM64, X86_64
     - Two's complement
     - See Section "4.5 Integers" of GCC_MANUAL.

   * - Any extended integer types that exist in the implementation
     - X86_64
     - __uint128_t
     - See Section "6.9 128-bit Integers" of GCC_MANUAL.

   * - The number, order, and encoding of bytes in any object
     - ARM64
     -
     - See Section "4.15 Architecture" of GCC_MANUAL and Chapter 5 "Data types and alignment" of ARM64_ABI_MANUAL.

   * - The number, order, and encoding of bytes in any object
     - X86_64
     -
     - See Section "4.15 Architecture" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - Whether a bit-field can straddle a storage-unit boundary
     - ARM64
     -
     - See Section "4.9 Structures, Unions, Enumerations, and Bit-Fields of GCC_MANUAL and Section "8.1.8 Bit-fields" of ARM64_ABI_MANUAL.

   * - Whether a bit-field can straddle a storage-unit boundary
     - X86_64
     -
     - See Section "4.9 Structures, Unions, Enumerations, and Bit-Fields" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - The order of allocation of bit-fields within a unit
     - ARM64
     -
     - See Section "4.9 Structures, Unions, Enumerations, and Bit-Fields of GCC_MANUAL and Section "8.1.8 Bit-fields" of ARM64_ABI_MANUAL.

   * - The order of allocation of bit-fields within a unit
     - X86_64
     -
     - See Section "4.9 Structures, Unions, Enumerations, and Bit-Fields" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - What constitutes an access to an object that has volatile-qualified type
     - ARM64, X86_64
     -
     - See Section "4.10 Qualifiers" of GCC_MANUAL.

   * - The values or expressions assigned to the macros specified in the headers <float.h>, <limits.h>, and <stdint.h>
     - ARM64
     -
     - See Section "4.15 Architecture" of GCC_MANUAL and Chapter 5 "Data types and alignment" of ARM64_ABI_MANUAL.

   * - The values or expressions assigned to the macros specified in the headers <float.h>, <limits.h>, and <stdint.h>
     - X86_64
     -
     - See Section "4.15 Architecture" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - Character not in the basic source character set is encountered in a source file, except in an identifier, a character constant, a string literal, a header name, a comment, or a preprocessing token that is never converted to a token
     - ARM64
     - UTF-8
     - See Section "1.1 Character sets" of CPP_MANUAL.
       We assume the locale is not restricting any UTF-8 characters being part of the source character set.

   * - The value of a char object into which has been stored any character other than a member of the basic execution character set
     - ARM64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and Section "8.1 Data types" of ARM64_ABI_MANUAL.

   * - The value of a char object into which has been stored any character other than a member of the basic execution character set
     - X86_64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - The value of an integer character constant containing more than one character or containing a character or escape sequence that does not map to a single-byte execution character
     - ARM64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and Section "8.1 Data types" of ARM64_ABI_MANUAL.

   * - The value of an integer character constant containing more than one character or containing a character or escape sequence that does not map to a single-byte execution character
     - X86_64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and Section "3.1.2 Data Representation" of X86_64_ABI_MANUAL.

   * - The mapping of members of the source character set
     - ARM64, X86_64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and the documentation for -finput-charset=charset in the same manual.

   * - The members of the source and execution character sets, except as explicitly specified in the Standard
     - ARM64, X86_64
     - UTF-8
     - See Section "4.4 Characters" of GCC_MANUAL

   * - The values of the members of the execution character set
     - ARM64, X86_64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and the documentation for -fexec-charset=charset in the same manual.

   * - How a diagnostic is identified
     - ARM64, X86_64
     -
     - See Section "4.1 Translation" of GCC_MANUAL.

   * - The places that are searched for an included < > delimited header, and how the places are specified or the header is identified
     - ARM64, X86_64
     -
     - See Chapter "2 Header Files" of CPP_MANUAL.

   * - How the named source file is searched for in an included " " delimited header
     - ARM64, X86_64
     -
     - See Chapter "2 Header Files" of CPP_MANUAL.

   * - How sequences in both forms of header names are mapped to headers or external source file names
     - ARM64, X86_64
     -
     - See Chapter "2 Header Files" of CPP_MANUAL.

   * - Whether the # operator inserts a \ character before the \ character that begins a universal character name in a character constant or string literal
     - ARM64, X86_64
     -
     - See Section "3.4 Stringizing" of CPP_MANUAL.

   * - The current locale used to convert a wide string literal into corresponding wide character codes
     - ARM64, X86_64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and Section "11.1 Implementation-defined behavior" of CPP_MANUAL.

   * - The value of a string literal containing a multibyte character or escape sequence not represented in the execution character set
     - X86_64
     -
     - See Section "4.4 Characters" of GCC_MANUAL and Section "11.1 Implementation-defined behavior" of CPP_MANUAL.

   * - The behavior on each recognized #pragma directive
     - ARM64, X86_64
     - pack, GCC visibility
     - See Section "4.13 Preprocessing Directives" of GCC_MANUAL and Section "7 Pragmas" of CPP_MANUAL.

   * - The method by which preprocessing tokens (possibly resulting from macro expansion) in a #include directive are combined into a header name
     - X86_64
     -
     - See Section "4.13 Preprocessing Directives" of GCC_MANUAL and Section "11.1 Implementation-defined behavior" of CPP_MANUAL.


Sizes of Integer types
______________________

Xen expects System V ABI on x86_64:
  https://gitlab.com/x86-psABIs/x86-64-ABI

Xen expects AAPCS32 on ARMv8-A AArch32 and ARMv7-A:
  https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst

Xen expects AAPCS64 LP64 on ARMv8-A AArch64:
  https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst

A summary table of data types, sizes and alignment is below:

.. list-table::
   :widths: 10 10 10 45
   :header-rows: 1

   * - Type
     - Size
     - Alignment
     - Architectures

   * - char 
     - 8 bits
     - 8 bits
     - x86_32, ARMv8-A AArch32, ARMv8-R AArch32, ARMv7-A, x86_64,
       ARMv8-A AArch64, RV64, PPC64

   * - short
     - 16 bits
     - 16 bits
     - x86_32, ARMv8-A AArch32, ARMv8-R AArch32, ARMv7-A, x86_64,
       ARMv8-A AArch64, RV64, PPC64

   * - int
     - 32 bits
     - 32 bits
     - x86_32, ARMv8-A AArch32, ARMv8-R AArch32, ARMv7-A, x86_64,
       ARMv8-A AArch64, RV64, PPC64

   * - long
     - 32 bits
     - 32 bits 
     - x86_32, ARMv8-A AArch32, ARMv8-R AArch32, ARMv7-A

   * - long
     - 64 bits
     - 64 bits 
     - x86_64, ARMv8-A AArch64, RV64, PPC64

   * - long long
     - 64-bit
     - 32-bit
     - x86_32

   * - long long
     - 64-bit
     - 64-bit
     - x86_64, ARMv8-A AArch64, RV64, PPC64, ARMv8-A AArch32, ARMv8-R
       AArch32, ARMv7-A

   * - pointer
     - 32-bit
     - 32-bit
     - x86_32, ARMv8-A AArch32, ARMv8-R AArch32, ARMv7-A

   * - pointer
     - 64-bit
     - 64-bit
     - x86_64, ARMv8-A AArch64, RV64, PPC64


END OF DOCUMENT.
