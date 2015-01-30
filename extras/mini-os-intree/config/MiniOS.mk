include $(MINI-OS_ROOT)/config/StdGNU.mk
include $(MINI-OS_ROOT)/Config.mk
CFLAGS += $(DEF_CFLAGS) $(ARCH_CFLAGS)
CPPFLAGS += $(DEF_CPPFLAGS) $(ARCH_CPPFLAGS) $(extra_incl)
ASFLAGS += $(DEF_ASFLAGS) $(ARCH_ASFLAGS)
LDFLAGS += $(DEF_LDFLAGS) $(ARCH_LDFLAGS)

# Override settings for this OS
PTHREAD_LIBS =
nosharedlibs=y
