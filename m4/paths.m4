AC_DEFUN([AX_XEN_EXPAND_CONFIG], [
dnl expand these early so we can use this for substitutions
test "x$prefix" = "xNONE" && prefix=$ac_default_prefix
test "x$exec_prefix" = "xNONE" && exec_prefix=${prefix}

dnl Use /var instead of /usr/local/var because there can be only one
dnl xenstored active at a time. All tools have to share this dir, even
dnl if they come from a different --prefix=.
if test "$localstatedir" = '${prefix}/var' ; then
    localstatedir=/var
fi

dnl expand exec_prefix or it will endup in substituted variables
bindir=`eval echo $bindir`
sbindir=`eval echo $sbindir`
libdir=`eval echo $libdir`

dnl
if test "x$sysconfdir" = 'x${prefix}/etc' ; then
    case "$host_os" in
         *freebsd*)
         sysconfdir=$prefix/etc
         ;;
         *solaris*)
         if test "$prefix" = "/usr" ; then
             sysconfdir=/etc
         else
             sysconfdir=$prefix/etc
         fi
         ;;
         *)
         sysconfdir=/etc
         ;;
    esac
fi

AC_ARG_WITH([initddir],
    AS_HELP_STRING([--with-initddir=DIR],
    [Path to directory with sysv runlevel scripts. [SYSCONFDIR/init.d]]),
    [initddir_path=$withval],
    [case "$host_os" in
         *linux*)
         if test -d $sysconfdir/rc.d/init.d ; then
             initddir_path=$sysconfdir/rc.d/init.d
         else
             initddir_path=$sysconfdir/init.d
         fi
         ;;
         *)
         initddir_path=$sysconfdir/rc.d
         ;;
     esac])

AC_ARG_WITH([sysconfig-leaf-dir],
    AS_HELP_STRING([--with-sysconfig-leaf-dir=SUBDIR],
    [Name of subdirectory in /etc to store runtime options for runlevel
    scripts and daemons such as xenstored.
    This should be either "sysconfig" or "default". [sysconfig]]),
    [config_leaf_dir=$withval],
    [config_leaf_dir=sysconfig
    if test ! -d /etc/sysconfig ; then config_leaf_dir=default ; fi])
CONFIG_LEAF_DIR=$config_leaf_dir
AC_SUBST(CONFIG_LEAF_DIR)

if test "$libexecdir" = '${exec_prefix}/libexec' ; then
    case "$host_os" in
         *netbsd*) ;;
         *)
         libexecdir='${exec_prefix}/lib'
         ;;
    esac
fi
dnl expand exec_prefix or it will endup in substituted variables
libexecdir=`eval echo $libexecdir`
dnl autoconf doc suggest to use a "package name" subdir
dnl This variable will be substituted in various .in files
LIBEXEC_BIN=`eval echo $libexecdir/$PACKAGE_TARNAME/bin`
AC_SUBST(LIBEXEC_BIN)

XEN_RUN_DIR=$localstatedir/run/xen
AC_SUBST(XEN_RUN_DIR)

XEN_LOG_DIR=$localstatedir/log/xen
AC_SUBST(XEN_LOG_DIR)

XEN_LIB_STORED=$localstatedir/lib/xenstored
AC_SUBST(XEN_LIB_STORED)

SHAREDIR=$prefix/share
AC_SUBST(SHAREDIR)

CONFIG_DIR=$sysconfdir
AC_SUBST(CONFIG_DIR)

INITD_DIR=$initddir_path
AC_SUBST(INITD_DIR)

XEN_CONFIG_DIR=$CONFIG_DIR/xen
AC_SUBST(XEN_CONFIG_DIR)

XEN_SCRIPT_DIR=$XEN_CONFIG_DIR/scripts
AC_SUBST(XEN_SCRIPT_DIR)

case "$host_os" in
*freebsd*) XEN_LOCK_DIR=$localstatedir/lib ;;
*netbsd*) XEN_LOCK_DIR=$localstatedir/lib ;;
*) XEN_LOCK_DIR=$localstatedir/lock ;;
esac
AC_SUBST(XEN_LOCK_DIR)

XEN_PAGING_DIR=$localstatedir/lib/xen/xenpaging
AC_SUBST(XEN_PAGING_DIR)
])
