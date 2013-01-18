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
PSSL_OBJS=aes.o sha1.o entropy.o ctr_drbg.o sha4.o

TARGET=vtpm.a
OBJS=vtpm.o vtpm_cmd.o vtpmblk.o vtpm_pcrs.o


CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)/build
CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)/tpm
CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)/crypto
CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)

$(TARGET): $(OBJS)
	ar -cr $@ $(OBJS) $(TPMEMU_OBJS) $(foreach obj,$(PSSL_OBJS),$(PSSL_DIR)/$(obj))

$(OBJS): vtpm_manager.h

vtpm_manager.h:
	ln -s ../vtpmmgr/vtpm_manager.h vtpm_manager.h

clean:
	-rm $(TARGET) $(OBJS) vtpm_manager.h

.PHONY: clean
