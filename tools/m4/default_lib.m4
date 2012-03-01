AC_DEFUN([AX_DEFAULT_LIB],
[AS_IF([test "\${exec_prefix}/lib" = "$libdir"],
    [AS_IF([test "$exec_prefix" = "NONE" && test "$prefix" != "NONE"],
        [exec_prefix=$prefix])
    AS_IF([test "$exec_prefix" = "NONE"], [exec_prefix=$ac_default_prefix])
    AS_IF([test -d "${exec_prefix}/lib64"], [
        LIB_PATH="lib64"
    ],[
        LIB_PATH="lib"
    ])
], [
    LIB_PATH="${libdir:`expr length "$exec_prefix" + 1`}"
])
AC_SUBST(LIB_PATH)])
