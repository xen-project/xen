include $(XEN_ROOT)/config/StdGNU.mk

DLOPEN_LIBS =

# No wget on FreeBSD base system
WGET = ftp

CONFIG_DIR = $(PREFIX)/etc
