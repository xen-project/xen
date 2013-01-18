AC_DEFUN([AX_CHECK_CURSES], [
AC_CHECK_HEADER([curses.h], [
    AC_CHECK_LIB([curses], [clear], [curses="y"], [curses="n"])
], [curses="n"])
AC_CHECK_HEADER([ncurses.h], [
    AC_CHECK_LIB([ncurses], [clear], [ncurses="y"], [ncurses="n"])
], [ncurses="n"])
AS_IF([test "$curses" = "n" && test "$ncurses" = "n"], [
    AC_MSG_ERROR([Unable to find a suitable curses library])
])
# Prefer ncurses over curses if both are present
AS_IF([test "$ncurses" = "y"], [
    CURSES_LIBS="-lncurses"
    AC_DEFINE([INCLUDE_CURSES_H], [<ncurses.h>], [Define curses header to use])
], [
    CURSES_LIBS="-lcurses"
    AC_DEFINE([INCLUDE_CURSES_H], [<curses.h>], [Define curses header to use])
])
AC_SUBST(CURSES_LIBS)
])
