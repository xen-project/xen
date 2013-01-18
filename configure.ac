#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Xen Hypervisor], m4_esyscmd([./version.sh ./xen/Makefile]),
    [xen-devel@lists.xen.org], [xen], [http://www.xen.org/])
AC_CONFIG_SRCDIR([./xen/common/kernel.c])
AC_PREFIX_DEFAULT([/usr])

AC_CONFIG_SUBDIRS([tools stubdom])

AC_OUTPUT()
