# -*- mode: Makefile; -*-

AS         = $(CROSS_COMPILE)gas
LD         = $(CROSS_COMPILE)gld
CC         = $(CROSS_COMPILE)gcc
CPP        = $(CROSS_COMPILE)gcc -E
AR         = $(CROSS_COMPILE)gar
RANLIB     = $(CROSS_COMPILE)granlib
NM         = $(CROSS_COMPILE)gnm
STRIP      = $(CROSS_COMPILE)gstrip
OBJCOPY    = $(CROSS_COMPILE)gobjcopy
OBJDUMP    = $(CROSS_COMPILE)gobjdump

GREP       = ggrep
SHELL      = bash

INSTALL      = ginstall
INSTALL_DIR  = $(INSTALL) -d -m0755
INSTALL_DATA = $(INSTALL) -m0644
INSTALL_PROG = $(INSTALL) -m0755

LIB64DIR = lib/amd64

SOCKET_LIBS = -lsocket
SONAME_LDFLAG = -h
SHLIB_CFLAGS = -static-libgcc -shared

ifneq ($(debug),y)
# Optimisation flags are overridable
CFLAGS ?= -O2 -fno-omit-frame-pointer
else
# Less than -O1 produces bad code and large stack frames
CFLAGS ?= -O1 -fno-omit-frame-pointer
endif

CFLAGS += -Wa,--divide
