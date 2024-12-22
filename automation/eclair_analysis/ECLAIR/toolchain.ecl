# Compilers.
-file_tag+={GCC_ARM64,"^/usr/bin/aarch64-linux-gnu-gcc-12$"}
-file_tag+={GCC_X86_64,"^/usr/bin/x86_64-linux-gnu-gcc-12$"}

# Manuals.
-setq=GCC_MANUAL,"https://gcc.gnu.org/onlinedocs/gcc-12.1.0/gcc.pdf"
-setq=CPP_MANUAL,"https://gcc.gnu.org/onlinedocs/gcc-12.1.0/cpp.pdf"
-setq=ARM64_ABI_MANUAL,"https://github.com/ARM-software/abi-aa/blob/60a8eb8c55e999d74dac5e368fc9d7e36e38dda4/aapcs64/aapcs64.rst"
-setq=X86_64_ABI_MANUAL,"https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build"
-setq=ARM64_LIBC_MANUAL,"https://www.gnu.org/software/libc/manual/pdf/libc.pdf"
-setq=X86_64_LIBC_MANUAL,"https://www.gnu.org/software/libc/manual/pdf/libc.pdf"
-setq=C99_STD,"ISO/IEC 9899:1999"

-doc_begin="
    __alignof__, __alignof: see Sections \"6.48 Alternate Keywords\" and \"6.44 Determining the Alignment of Functions, Types or Variables\" of "GCC_MANUAL".
    asm, __asm__: see Sections \"6.48 Alternate Keywords\" and \"6.47 How to Use Inline Assembly Language in C Code\" of "GCC_MANUAL".
    __attribute__: see Section \"6.39 Attribute Syntax\" of "GCC_MANUAL".
    __builtin_offsetof: see Section \"6.53 Support for offsetof\" of "GCC_MANUAL".
    __builtin_types_compatible_p: see Section \"6.59 Other Built-in Functions Provided by GCC\" of "GCC_MANUAL".
    __builtin_va_arg: non-documented GCC extension.
    __const__, __inline__, __inline: see Section \"6.48 Alternate Keywords\" of "GCC_MANUAL".
    _Static_assert: see Section \"2.1 C Language\" of "GCC_MANUAL".
    typeof, __typeof__: see Section \"6.7 Referring to a Type with typeof\" of "GCC_MANUAL".
    __volatile__: see Sections \"6.48 Alternate Keywords\" and \"6.47.2.1 Volatile\" of "GCC_MANUAL".
"
-name_selector+={alignof, "^(__alignof__|__alignof)$"}
-name_selector+={asm, "^(__asm__|asm)$"}
-name_selector+={attribute, "^__attribute__$"}
-name_selector+={builtin_offsetof, "^__builtin_offsetof$"}
-name_selector+={builtin_types_p, "^__builtin_types_compatible_p$"}
-name_selector+={builtin_va_arg, "^__builtin_va_arg$"}
-name_selector+={const, "^__const__$"}
-name_selector+={inline, "^(__inline__|__inline)$"}
-name_selector+={static_assert, "^_Static_assert$"}
-name_selector+={typeof, "^(__typeof__|typeof)$"}
-name_selector+={volatile, "^__volatile__$"}

-config=STD.tokenext,behavior+={c99, GCC_ARM64||GCC_X86_64,
"alignof||
asm||
attribute||
builtin_offsetof||
builtin_types_p||
builtin_va_arg||
const||
inline||
static_assert||
typeof||
volatile"
}
-doc_end

-doc_begin="Non-documented GCC extension."
-config=STD.emptinit,behavior+={c99,GCC_ARM64,specified}
-config=STD.emptinit,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.24 Arithmetic on void- and Function-Pointers\" of "GCC_MANUAL"."
-config=STD.vptrarth,behavior+={c99,GCC_ARM64,specified}
-config=STD.vptrarth,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.1 Statements and Declarations in Expressions\" of "GCC_MANUAL"."
-config=STD.stmtexpr,behavior+={c99,GCC_ARM64,specified}
-config=STD.stmtexpr,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.19 Structures with No Members\" of "GCC_MANUAL"."
-config=STD.anonstct,behavior+={c99,GCC_ARM64,specified}
-config=STD.anonstct,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.18 Arrays of Length Zero\" of "GCC_MANUAL"."
-config=STD.arayzero,behavior+={c99,GCC_ARM64,specified}
-config=STD.arayzero,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.8 Conditionals with Omitted Operands\" of "GCC_MANUAL"."
-config=STD.bincondl,behavior+={c99,GCC_ARM64,specified}
-config=STD.bincondl,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.30 Case Ranges\" of "GCC_MANUAL"."
-config=STD.caseuplw,behavior+={c99,GCC_ARM64,specified}
-config=STD.caseuplw,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="See Section \"6.63 Unnamed Structure and Union Fields\" of "GCC_MANUAL"."
-config=STD.anonfild,behavior+={c99,GCC_ARM64,specified}
-config=STD.anonfild,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="Non-documented GCC extension."
-config=STD.emptdecl,behavior+={c99,GCC_ARM64,specified}
-config=STD.emptdecl,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="Non-documented GCC extension."
-config=STD.emptenum,behavior+={c99,GCC_ARM64,specified}
-doc_end

-doc_begin="Non-documented GCC extension."
-config=STD.pteincmp,behavior+={c99,GCC_ARM64,specified}
-config=STD.pteincmp,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="Non-documented GCC extension."
-config=STD.funojptr,behavior+={c99,GCC_X86_64,specified}
-doc_end

-doc_begin="
    ext_c_missing_varargs_arg: see Section \"6.21 Macros with a Variable Number of Arguments\" of "GCC_MANUAL".
    ext_enum_value_not_int: non-documented GCC extension.
    ext_flexible_array_in_array: see Section \"6.18 Arrays of Length Zero\" of "GCC_MANUAL".
    ext_flexible_array_in_struct: see Section \"6.18 Arrays of Length Zero\" of "GCC_MANUAL".
    ext_forward_ref_enum_def: see Section \"6.49 Incomplete enum Types\" of "GCC_MANUAL".
    ext_gnu_array_range: see Section \"6.29 Designated Initializers\" of "GCC_MANUAL".
    ext_gnu_statement_expr_macro: see Section \"6.1 Statements and Declarations in Expressions\" of "GCC_MANUAL".
    ext_named_variadic_macro: see Section \"6.21 Macros with a Variable Number of Arguments\" of "GCC_MANUAL".
    ext_paste_comma: see Section \"6.21 Macros with a Variable Number of Arguments\" of "GCC_MANUAL".
    ext_return_has_void_expr: see the documentation for -Wreturn-type in Section \"3.8 Options to Request or Suppress Warnings\" of "GCC_MANUAL".
    ext_sizeof_alignof_void_type: see Section \"6.24 Arithmetic on void- and Function-Pointers\" of "GCC_MANUAL".
"
-name_selector+={ext_c_missing_varargs_arg, "^ext_c_missing_varargs_arg$"}
-name_selector+={ext_enum_value_not_int, "^ext_enum_value_not_int$"}
-name_selector+={ext_flexible_array_in_array, "^ext_flexible_array_in_array$"}
-name_selector+={ext_flexible_array_in_struct, "^ext_flexible_array_in_struct$"}
-name_selector+={ext_forward_ref_enum_def, "^ext_forward_ref_enum_def$"}
-name_selector+={ext_gnu_array_range, "^ext_gnu_array_range$"}
-name_selector+={ext_gnu_statement_expr_macro, "^ext_gnu_statement_expr_macro$"}
-name_selector+={ext_named_variadic_macro, "^ext_named_variadic_macro$"}
-name_selector+={ext_paste_comma, "^ext_paste_comma$"}
-name_selector+={ext_return_has_void_expr, "^ext_return_has_void_expr$"}
-name_selector+={ext_sizeof_alignof_void_type, "^ext_sizeof_alignof_void_type$"}

-config=STD.diag,behavior+={c99,GCC_ARM64,
"ext_c_missing_varargs_arg||
ext_forward_ref_enum_def||
ext_gnu_array_range||
ext_gnu_statement_expr_macro||
ext_named_variadic_macro||
ext_paste_comma||
ext_return_has_void_expr||
ext_sizeof_alignof_void_type"
}
-config=STD.diag,behavior+={c99,GCC_X86_64,
"ext_c_missing_varargs_arg||
ext_enum_value_not_int||
ext_flexible_array_in_array||
ext_flexible_array_in_struct||
ext_gnu_array_range||
ext_gnu_statement_expr_macro||
ext_named_variadic_macro||
ext_paste_comma||
ext_return_has_void_expr||
ext_sizeof_alignof_void_type"
}
-doc_end

-doc_begin="The maximum size of an object is defined in the MAX_SIZE macro, and for a 32 bit architecture is 8MB.
    The maximum size for an array is defined in the PTRDIFF_MAX and in a 32 bit architecture is 2^30-1.
    See occurrences of these macros in "GCC_MANUAL"."
-config=STD.byteobjt,behavior+={c99, GCC_ARM64, 8388608}
-config=STD.byteobjt,behavior+={c99, GCC_X86_64, 8388608}
-doc_end

-doc_begin="See Section \"11.2 Implementation limits\" of "CPP_MANUAL"."
-config=STD.charline,behavior+={c99, GCC_ARM64, 5000}
-config=STD.charline,behavior+={c99, GCC_X86_64, 12000}
-doc_end

-doc_begin="See Section \"11.2 Implementation limits\" of "CPP_MANUAL"."
-config=STD.inclnest,behavior+={c99, GCC_ARM64, 24}
-config=STD.inclnest,behavior+={c99, GCC_X86_64, 32}
-doc_end

-doc_begin="FIXME: why is C90 used?"
-config=STD.ppifnest,behavior+={c90, GCC_X86_64, 32}
-doc_end

-doc_begin="See Section \"4.12 Statements\" of "GCC_MANUAL"."
-config=STD.caselimt,behavior+={c99, GCC_X86_64, 1500}
-doc_end

-doc_begin="See Section \"6.9 128-bit Integers\" of "GCC_MANUAL"."
-config=STD.stdtypes,behavior+={c99, GCC_X86_64, "__uint128_t"}
-doc_end

-doc_begin="FIXME: Non-documented GCC extension?"
-config=STD.charescp,behavior={c99, GCC_X86_64, "^m$"}
-doc_end

-doc_begin="See Section \"4.9 Structures, Unions, Enumerations, and Bit-Fields\" of "GCC_MANUAL"."
-config=STD.bitfldtp, +behavior={c99, GCC_ARM64, "unsigned char;unsigned short;unsigned long;unsigned long long"}
-config=STD.bitfldtp, +behavior={c99, GCC_X86_64, "unsigned char;unsigned short;unsigned long;enum"}
-doc_end

-doc_begin="
    #pragma pack: see Section \"6.62.11 Structure-Layout Pragmas\" of "GCC_MANUAL".
    #pragma GCC visibility: see Section \"6.62.14 Visibility Pragmas\" of "GCC_MANUAL".
"
-config=STD.nonstdc,behavior={c99, GCC_ARM64, "^(pack\\(|GCC visibility (push|pop)).*$"}
-config=STD.nonstdc,behavior={c99, GCC_X86_64, "^(pack\\(|GCC visibility (push|pop)).*$"}
-doc_end

-doc_begin="See Section \"1.1 Character sets\" of "CPP_MANUAL".  We assume the locale is not restricting any UTF-8 characters being part of the source character set."
-config=STD.charset,behavior={c99, GCC_ARM64, "utf8"}
-doc_end

-doc_begin="See Section \"4.3 Identifiers\" of "GCC_MANUAL"."
-config=STD.extidsig, behavior+={c99, GCC_ARM64, "63"}
-config=STD.extidsig, behavior+={c99, GCC_X86_64, "63"}
-doc_end

#
# Documentation for relied-upon implementation-defined behaviors (Dir 1.1)
#

-doc_begin="See Section \"4.4 Characters\" of "GCC_MANUAL" and Section \"8.1 Data types\" of "ARM64_ABI_MANUAL"."
-config=STD.bytebits,behavior={c99, GCC_ARM64, "8"}
-config=STD.charsobj,behavior={c99, GCC_ARM64, "utf8"}
-config=STD.charsval,behavior={c99, GCC_ARM64, "utf8"}
-doc_end

-doc_begin="See Section \"4.4 Characters\" of "GCC_MANUAL" and Section \"3.1.2 Data Representation\" of "X86_64_ABI_MANUAL"."
-config=STD.bytebits,behavior={c99, GCC_X86_64, "8"}
-config=STD.charsobj,behavior={c99, GCC_X86_64, "utf8"}
-config=STD.charsval,behavior={c99, GCC_X86_64, "utf8"}
-doc_end

-doc_begin="See Section \"4.4 Characters\" of "GCC_MANUAL" and the documentation for -finput-charset=charset in the same manual."
-config=STD.charsmap,behavior={c99, GCC_ARM64, "specified"}
-config=STD.charsmap,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.4 Characters\" of "GCC_MANUAL" and the documentation for -fexec-charset=charset and -finput-charset=charset in the same manual."
-config=STD.charsmem,behavior={c99, GCC_ARM64, "utf8"}
-config=STD.charsmem,behavior={c99, GCC_X86_64, "utf8"}
-doc_end

-doc_begin="See Section \"4.1 Translation\" of "GCC_MANUAL"."
-config=STD.diagidnt,behavior={c99, GCC_ARM64, "specified"}
-config=STD.diagidnt,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.4 Characters\" of "GCC_MANUAL" and the documentation for -fexec-charset=charset in the same manual."
-config=STD.execvals,behavior={c99, GCC_ARM64, "specified"}
-config=STD.execvals,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="Given that Xen is compiled in hosted mode, ECLAIR cannot exclude the independency from program termination implementation-defined behavior.  See \"Section 25.7 Program Termination\" of "ARM64_LIBC_MANUAL"."
-config=STD.exitstat,behavior={c99, GCC_ARM64, "specified"}
-doc_end

-doc_begin="Given that Xen is compiled in hosted mode, ECLAIR cannot exclude the independency from program termination implementation-defined behavior.  See \"Section 25.7 Program Termination\" of "X86_64_LIBC_MANUAL"."
-config=STD.exitstat,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Chapter \"2 Header Files\" of "CPP_MANUAL"."
-config=STD.inclangl,behavior={c99, GCC_ARM64, "specified"}
-config=STD.inclangl,behavior={c99, GCC_X86_64, "specified"}
-config=STD.inclfile,behavior={c99, GCC_ARM64, "specified"}
-config=STD.inclfile,behavior={c99, GCC_X86_64, "specified"}
-config=STD.inclhead,behavior={c99, GCC_ARM64, "specified"}
-config=STD.inclhead,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.5 Integers\" of "GCC_MANUAL"."
-config=STD.signdint,behavior={c99, GCC_ARM64, "specified"}
-config=STD.signdint,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.15 Architecture\" of "GCC_MANUAL" and Chapter \"5   Data types and alignment\" of "ARM64_ABI_MANUAL"."
-config=STD.objbytes,behavior={c99, GCC_ARM64, "specified"}
-doc_end

-doc_begin="See Section \"4.15 Architecture\" of "GCC_MANUAL" and Section \"3.1.2 Data Representation\" of "X86_64_ABI_MANUAL"."
-config=STD.objbytes,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"3.4 Stringizing\" of "CPP_MANUAL"."
-config=STD.stringfy,behavior={c99, GCC_ARM64, "specified"}
-config=STD.stringfy,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.9 Structures, Unions, Enumerations, and Bit-Fields\"
 of "GCC_MANUAL" and Section \"8.1.8 Bit-fields\" of "ARM64_ABI_MANUAL"."
-config=STD.bitfldby,+behavior={c99, GCC_ARM64, "specified"}
-config=STD.bitfldor,+behavior={c99, GCC_ARM64, "specified"}
-doc_end

-doc_begin="See Section \"4.9 Structures, Unions, Enumerations, and Bit-Fields\"
 of "GCC_MANUAL" and Section \"3.1.2 Data Representation\" of "X86_64_ABI_MANUAL"."
-config=STD.bitfldby,+behavior={c99, GCC_X86_64, "specified"}
-config=STD.bitfldor,+behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.10 Qualifiers\" of "GCC_MANUAL"."
-config=STD.volatltp,+behavior={c99, GCC_ARM64, "specified"}
-config=STD.volatltp,+behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.15 Architecture\" of "GCC_MANUAL" and Chapter \"5   Data types and alignment\" of "ARM64_ABI_MANUAL"."
-config=STD.stdmacro,behavior={c99, GCC_ARM64, "specified"}
-doc_end

-doc_begin="See Section \"4.15 Architecture\" of "GCC_MANUAL" and Section \"3.1.2 Data Representation\" of "X86_64_ABI_MANUAL"."
-config=STD.stdmacro,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.4 Characters\" of "GCC_MANUAL" and Section \"11.1 Implementation-defined behavior\" of "CPP_MANUAL"."
-config=STD.widestng,behavior={c99, GCC_ARM64, "specified"}
-config=STD.widestng,behavior={c99, GCC_X86_64, "specified"}
-config=STD.multbtsl,behavior={c99, GCC_X86_64, "specified"}
-doc_end

-doc_begin="See Section \"4.13 Preprocessing Directives\" of "GCC_MANUAL" and Section \"7 Pragmas\" of "CPP_MANUAL"."
-config=STD.pragmdir,behavior={c99, GCC_ARM64, "^(pack\\(|GCC visibility (push|pop)).*$"}
-config=STD.pragmdir,behavior={c99, GCC_X86_64, "^(pack\\(|GCC visibility (push|pop)).*$"}
-doc_end

-doc_begin="See Section \"6.9 128-bit Integers\" of "GCC_MANUAL"."
-config=STD.extinttp,behavior={c99, GCC_X86_64, "__uint128_t"}
-doc_end

-doc_begin="See Section \"4.13 Preprocessing Directives\" of "GCC_MANUAL" and Section \"11.1 Implementation-defined behavior\" of "CPP_MANUAL"."
-config=STD.inclexpd,behavior={c99, GCC_X86_64, "specified"}
-doc_end
