AC_DEFUN([AX_DOCS_TOOL_PROG], [
dnl
    AC_ARG_VAR([$1], [Path to $2 tool])
    AC_PATH_PROG([$1], [$2])
    AS_IF([! test -x "$ac_cv_path_$1"], [
        AC_MSG_WARN([$2 is not available so some documentation won't be built])
    ])
])

AC_DEFUN([AX_DOCS_TOOL_PROGS], [
dnl
    AC_ARG_VAR([$1], [Path to $2 tool])
    AC_PATH_PROGS([$1], [$3])
    AS_IF([! test -x "$ac_cv_path_$1"], [
        AC_MSG_WARN([$2 is not available so some documentation won't be built])
    ])
])
