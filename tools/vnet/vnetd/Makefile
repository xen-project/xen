# -*- mode: Makefile; -*-
#----------------------------------------------------------------------------
# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>.
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or  (at your option) any later version. This library is 
# distributed in the  hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#----------------------------------------------------------------------------

all: vnetd

#----------------------------------------------------------------------------

XEN_ROOT  = ../../..
include $(XEN_ROOT)/tools/Rules.mk

VNETD_INSTALL_DIR = /usr/sbin

LIB_DIR = $(XEN_LIBXUTIL)
VNET_DIR = ../vnet-module

INCLUDES += -I$(LIB_DIR)
INCLUDES += -I$(VNET_DIR)

#----------------------------------------------------------------------------
# GC.
GC_DIR:=../gc/install
GC_INCLUDE:= $(GC_DIR)/include
GC_LIB_DIR:=$(GC_DIR)/lib

INCLUDES += -I$(GC_INCLUDE)
#LIBS += -L$(GC_LIB_DIR)
CPPFLAGS += -D USE_GC

#----------------------------------------------------------------------------
CFLAGS += -Wall
CFLAGS += $(INCLUDES) $(LIBS)

LDFLAGS += $(LIBS)

# Dependencies. Gcc generates them for us.
CFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d

vpath %.c $(LIB_DIR)

IPATHS:=$(INCLUDES:-I=)
vpath %.h $(IPATHS)

#----------------------------------------------------------------------------
VNETD_SRC:=
VNETD_SRC+= connection.c
VNETD_SRC+= marshal.c
VNETD_SRC+= select.c
VNETD_SRC+= timer.c
VNETD_SRC+= vcache.c
VNETD_SRC+= vnetd.c

LIB_SRC:=
LIB_SRC+= allocate.c
LIB_SRC+= enum.c
LIB_SRC+= file_stream.c
LIB_SRC+= hash_table.c
LIB_SRC+= iostream.c
LIB_SRC+= lexis.c
LIB_SRC+= socket_stream.c
LIB_SRC+= string_stream.c
LIB_SRC+= sxpr.c
LIB_SRC+= sys_net.c
LIB_SRC+= sys_string.c
LIB_SRC+= util.c

VNETD_SRC+=$(LIB_SRC)

VNETD_OBJ := $(VNETD_SRC:.c=.o)

#VNETD_LIBS:= $(GC_LIB_DIR)/libgc.so.1.0.2
#VNETD_LIBS:= -lgc
VNETD_LIBS:= $(GC_LIB_DIR)/libgc.a

vnetd: $(VNETD_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(VNETD_LIBS) -ldl -lpthread

install: vnetd
	mkdir -p $(DESTDIR)$(VNETD_INSTALL_DIR)
	install -m 0755 vnetd $(DESTDIR)$(VNETD_INSTALL_DIR)

clean:
	-rm -f *.a *.o *~
	-rm -f vnetd
	-rm -f $(PROG_DEP)

-include $(PROG_DEP)
