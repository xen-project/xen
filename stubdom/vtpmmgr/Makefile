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

PSSL_DIR=../polarssl-$(XEN_TARGET_ARCH)/library
PSSL_OBJS=aes.o sha1.o entropy.o ctr_drbg.o bignum.o sha4.o havege.o timing.o entropy_poll.o

TARGET=vtpmmgr.a
OBJS=vtpmmgr.o vtpm_cmd_handler.o vtpm_storage.o init.o tpmrsa.o tpm.o log.o

CFLAGS+=-Werror -Iutil -Icrypto -Itcs
CFLAGS+=-Wno-declaration-after-statement -Wno-unused-label

build: $(TARGET)
$(TARGET): $(OBJS)
	ar -rcs $@ $^ $(foreach obj,$(PSSL_OBJS),$(PSSL_DIR)/$(obj))

clean:
	rm -f $(TARGET) $(OBJS)

distclean: clean

.PHONY: clean distclean
