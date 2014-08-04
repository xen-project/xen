AC_DEFUN([AX_XEN_EXPAND_CONFIG], [
dnl expand these early so we can use this for substitutions
test "x$prefix" = "xNONE" && prefix=$ac_default_prefix
test "x$exec_prefix" = "xNONE" && exec_prefix=${prefix}

BINDIR=$prefix/bin
AC_SUBST(BINDIR)

SBINDIR=$prefix/sbin
AC_SUBST(SBINDIR)

dnl XXX: this should be changed to use the passed $libexec
dnl but can be done as a second step
LIBEXEC=$prefix/lib/xen/bin
AC_SUBST(LIBEXEC)

LIBDIR=`eval echo $libdir`
AC_SUBST(LIBDIR)

XEN_RUN_DIR=/var/run/xen
AC_SUBST(XEN_RUN_DIR)

XEN_LOG_DIR=/var/log/xen
AC_SUBST(XEN_LOG_DIR)

XEN_LIB_STORED=/var/lib/xenstored
AC_SUBST(XEN_LIB_STORED)

SHAREDIR=$prefix/share
AC_SUBST(SHAREDIR)

PRIVATE_PREFIX=$LIBDIR/xen
AC_SUBST(PRIVATE_PREFIX)

PKG_XEN_PREFIX=$LIBDIR/xen
AC_SUBST(PKG_XEN_PREFIX)

PRIVATE_BINDIR=$PRIVATE_PREFIX/bin
AC_SUBST(PRIVATE_BINDIR)

XENFIRMWAREDIR=$prefix/lib/xen/boot
AC_SUBST(XENFIRMWAREDIR)

CONFIG_DIR=/etc
AC_SUBST(CONFIG_DIR)

XEN_CONFIG_DIR=$CONFIG_DIR/xen
AC_SUBST(XEN_CONFIG_DIR)

XEN_SCRIPT_DIR=$XEN_CONFIG_DIR/scripts
AC_SUBST(XEN_SCRIPT_DIR)

XEN_LOCK_DIR=/var/lock
AC_SUBST(XEN_LOCK_DIR)

XEN_RUN_DIR=/var/run/xen
AC_SUBST(XEN_RUN_DIR)

XEN_PAGING_DIR=/var/lib/xen/xenpaging
AC_SUBST(XEN_PAGING_DIR)
])
