include $(XEN_ROOT)/config/StdGNU.mk

# Override settings for this OS
LIBEXEC = $(PREFIX)/libexec
PRIVATE_BINDIR = $(BINDIR)

DLOPEN_LIBS =

XEN_LOCK_DIR = /var/lib

WGET = ftp
