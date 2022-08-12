include $(XEN_ROOT)/config/StdGNU.mk

XEN_ELF_SUB_FLAVOR = _fbsd

# No wget on FreeBSD base system
WGET = ftp
PKG_INSTALLDIR = ${prefix}/libdata/pkgconfig

# Add the default pkg install path
APPEND_LIB += /usr/local/lib
APPEND_INCLUDES += /usr/local/include
