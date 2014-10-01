# Copyright (c) 2010-2012 United States Government, as represented by
# the Secretary of Defense.  All rights reserved.
#
# THIS SOFTWARE AND ITS DOCUMENTATION ARE PROVIDED AS IS AND WITHOUT
# ANY EXPRESS OR IMPLIED WARRANTIES WHATSOEVER. ALL WARRANTIES
# INCLUDING, BUT NOT LIMITED TO, PERFORMANCE, MERCHANTABILITY, FITNESS
# FOR A PARTICULAR  PURPOSE, AND NONINFRINGEMENT ARE HEREBY
# DISCLAIMED. USERS ASSUME THE ENTIRE RISK AND LIABILITY OF USING THE
# SOFTWARE.
#

XEN_ROOT=../..

TARGET=vtpmmgr.a
OBJS=vtpmmgr.o vtpm_cmd_handler.o init.o tpmrsa.o tpm.o log.o
OBJS += vtpm_disk.o disk_tpm.o disk_io.o disk_crypto.o disk_read.o disk_write.o
OBJS += mgmt_authority.o

CFLAGS+=-Werror -Iutil -Icrypto -Itcs
CFLAGS+=-Wno-declaration-after-statement -Wno-unused-label

build: $(TARGET)
$(TARGET): $(OBJS)
	ar -rcs $@ $^

install:
	$(INSTALL_DIR) "$(DESTDIR)$(LIBEXEC_BIN)"
	$(INSTALL_PROG) calc.pl "$(DESTDIR)$(LIBEXEC_BIN)"
	$(INSTALL_PROG) manage-vtpmmgr.pl "$(DESTDIR)$(LIBEXEC_BIN)"

clean:
	rm -f $(TARGET) $(OBJS)

distclean: clean

.PHONY: clean distclean
