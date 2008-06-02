# Common Makefile for mini-os.
#
# Every architecture directory below mini-os/arch has to have a
# Makefile and a arch.mk.
#

export XEN_ROOT = ../..
include $(XEN_ROOT)/Config.mk

ifneq ($(stubdom),y)
include Config.mk
endif

# Include common mini-os makerules.
include minios.mk

# Set tester flags
# CFLAGS += -DBLKTEST_WRITE

# Define some default flags for linking.
LDLIBS := 
APP_LDLIBS := 
LDARCHLIB := -L$(TARGET_ARCH_DIR) -l$(ARCH_LIB_NAME)
LDFLAGS_FINAL := -T $(TARGET_ARCH_DIR)/minios-$(XEN_TARGET_ARCH).lds

# Prefix for global API names. All other symbols are localised before
# linking with EXTRA_OBJS.
GLOBAL_PREFIX := xenos_
EXTRA_OBJS =

TARGET := mini-os

# Subdirectories common to mini-os
SUBDIRS := lib xenbus console

# The common mini-os objects to build.
APP_OBJS :=
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
OBJS += $(patsubst %.c,%.o,$(wildcard lib/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard xenbus/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard console/*.c))


.PHONY: default
default: $(TARGET)

# Create special architecture specific links. The function arch_links
# has to be defined in arch.mk (see include above).
ifneq ($(ARCH_LINKS),)
$(ARCH_LINKS):
	$(arch_links)
endif

.PHONY: links
links:	$(ARCH_LINKS)
	[ -e include/xen ] || ln -sf ../../../xen/include/public include/xen

.PHONY: arch_lib
arch_lib:
	$(MAKE) --directory=$(TARGET_ARCH_DIR) || exit 1;

ifeq ($(lwip),y)
# lwIP library
LWC	:= $(shell find $(LWIPDIR)/ -type f -name '*.c')
LWC	:= $(filter-out %6.c %ip6_addr.c %ethernetif.c, $(LWC))
LWC	+= lwip-arch.c lwip-net.c
LWO	:= $(patsubst %.c,%.o,$(LWC))

lwip.a: $(LWO)
	$(RM) $@
	$(AR) cqs $@ $^

OBJS += lwip.a
endif

OBJS := $(filter-out main.o lwip%.o $(LWO), $(OBJS))

ifeq ($(libc),y)
APP_LDLIBS += -L$(XEN_ROOT)/stubdom/libxc -whole-archive -lxenguest -lxenctrl -no-whole-archive
APP_LDLIBS += -lpci
APP_LDLIBS += -lz
APP_LDLIBS += -lm
LDLIBS += -lc
endif

ifneq ($(APP_OBJS)-$(lwip),-y)
OBJS := $(filter-out daytime.o, $(OBJS))
endif

$(TARGET)_app.o: $(APP_OBJS) app.lds
	$(LD) -r -d $(LDFLAGS) $^ $(APP_LDLIBS) --undefined app_main -o $@

$(TARGET): links $(OBJS) $(TARGET)_app.o arch_lib
	$(LD) -r $(LDFLAGS) $(HEAD_OBJ) $(TARGET)_app.o $(OBJS) $(LDARCHLIB) $(LDLIBS) -o $@.o
	$(OBJCOPY) -w -G $(GLOBAL_PREFIX)* -G _start $@.o $@.o
	$(LD) $(LDFLAGS) $(LDFLAGS_FINAL) $@.o $(EXTRA_OBJS) -o $@
	gzip -f -9 -c $@ >$@.gz

.PHONY: clean arch_clean

arch_clean:
	$(MAKE) --directory=$(TARGET_ARCH_DIR) clean || exit 1;

clean:	arch_clean
	for dir in $(SUBDIRS); do \
		rm -f $$dir/*.o; \
	done
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	find . -type l | xargs rm -f
	$(RM) lwip.a $(LWO)
	rm -f tags TAGS


define all_sources
     ( find . -follow -name SCCS -prune -o -name '*.[chS]' -print )
endef

.PHONY: cscope
cscope:
	$(all_sources) > cscope.files
	cscope -k -b -q
    
.PHONY: tags
tags:
	$(all_sources) | xargs ctags

.PHONY: TAGS
TAGS:
	$(all_sources) | xargs etags

