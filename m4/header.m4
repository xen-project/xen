AC_DEFUN([AX_FIND_HEADER], [
ax_found=0
m4_foreach_w([header], $2, [
    AS_IF([test "$ax_found" = "0"], [
        AC_CHECK_HEADER(header, [
            AC_DEFINE($1, [<header>], [Header path for $1])
            ax_found=1])
    ])
])
AS_IF([test "$ax_found" = "0"], [
    AC_MSG_ERROR([No header found from list $2])
])
])
