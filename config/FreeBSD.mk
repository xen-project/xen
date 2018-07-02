include $(XEN_ROOT)/config/StdGNU.mk

# No wget on FreeBSD base system
WGET = ftp
PKG_INSTALLDIR = ${prefix}/libdata/pkgconfig

# Add the default pkg install path
APPEND_LIB += /usr/local/lib
APPEND_INCLUDES += /usr/local/include
