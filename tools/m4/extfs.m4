AC_DEFUN([AX_CHECK_EXTFS], [
AC_CHECK_HEADER([ext2fs/ext2fs.h], [
AC_CHECK_LIB([ext2fs], [ext2fs_open2], [
    AC_DEFINE([INCLUDE_EXTFS_H], [<ext2fs/ext2fs.h>],
              [Define extfs header to use])
    EXTFS_LIBS="-lext2fs"
])
])
dnl This is a temporary hack for CentOS 5.x, which split the ext4 support
dnl of ext2fs in a different package. Once CentOS 5.x is no longer supported
dnl we can remove this.
AC_CHECK_HEADER([ext4fs/ext2fs.h], [
AC_CHECK_LIB([ext4fs], [ext2fs_open2], [
    AC_DEFINE([INCLUDE_EXTFS_H], [<ext4fs/ext2fs.h>],
              [Define extfs header to use])
    EXTFS_LIBS="-lext4fs"
])
])
AC_SUBST(EXTFS_LIBS)
])
