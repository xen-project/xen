AC_DEFUN([AX_CHECK_FETCHER], [
AC_PATH_PROG([WGET],[wget], [no])
AS_IF([test x"$WGET" != x"no"], [
    FETCHER="$WGET -c -O"
], [
    AC_PATH_PROG([FTP],[ftp], [no])
    AS_IF([test x"$FTP" != x"no"], [
        FETCHER="$FTP -o"
    ], [
        AC_MSG_ERROR([cannot find wget or ftp])
    ])
])
AC_SUBST(FETCHER)
])
