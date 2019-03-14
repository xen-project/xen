AC_DEFUN([AX_CHECK_FETCHER], [
AC_PATH_PROG([WGET],[wget], [no])
AC_PATH_PROG([FALSE],[false], [/bin/false])
AS_IF([test x"$WGET" != x"no"], [
    FETCHER="$WGET -c -O"
], [
    AC_PATH_PROG([FTP],[ftp], [no])
    AS_IF([test x"$FTP" != x"no"], [
        FETCHER="$FTP -o"
    ], [
        FETCHER="$FALSE"
        AC_MSG_WARN([cannot find wget or ftp])
    ])
])
AC_SUBST(FETCHER)
])
