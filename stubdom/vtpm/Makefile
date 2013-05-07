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

TARGET=vtpm.a
OBJS=vtpm.o vtpm_cmd.o vtpmblk.o vtpm_pcrs.o


CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)/build
CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)/tpm
CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)/crypto
CPPFLAGS+=-I../tpm_emulator-$(XEN_TARGET_ARCH)

$(TARGET): $(OBJS)
	ar -cr $@ $(OBJS)

$(OBJS): vtpm_manager.h

vtpm_manager.h:
	ln -s ../vtpmmgr/vtpm_manager.h vtpm_manager.h

clean:
	rm -f $(TARGET) $(OBJS) vtpm_manager.h

.PHONY: clean
