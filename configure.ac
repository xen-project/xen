#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor], m4_esyscmd([./version.sh ./xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([./xen/common/kernel.c])
AC_CONFIG_FILES([
	config/Toplevel.mk
	config/Paths.mk
])

AC_CANONICAL_HOST

m4_include([m4/features.m4])
m4_include([m4/subsystem.m4])
m4_include([m4/paths.m4])

AX_XEN_EXPAND_CONFIG()

dnl mini-os is only ported to certain platforms
case "$host_cpu" in
    i[[3456]]86|x86_64)
        arch_enable_stubdom=y
        ;;
    *)
        arch_enable_stubdom=n
        ;;
esac

dnl Stubdomains need some work in order to compile on FreeBSD
case "$host_os" in
    freebsd*)
        arch_enable_stubdom=n
        ;;
esac

AX_SUBSYSTEM_DEFAULT_ENABLE([xen])
AX_SUBSYSTEM_DEFAULT_ENABLE([tools])
AX_SUBSYSTEM_CONDITIONAL([stubdom], $arch_enable_stubdom)
AX_SUBSYSTEM_DEFAULT_ENABLE([docs])

AX_SUBSYSTEM_FINISH

AC_OUTPUT()
