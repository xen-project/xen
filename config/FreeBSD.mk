include $(XEN_ROOT)/config/StdGNU.mk

# No wget on FreeBSD base system
WGET = ftp
PKG_INSTALLDIR = ${prefix}/libdata/pkgconfig
