########################################
# x86-specific definitions

ifneq ($(filter -DHAVE_AS_QUOTED_SYM,$(XEN_CFLAGS)),)
object_label_flags = '-D__OBJECT_LABEL__=$(subst $(BASEDIR)/,,$(CURDIR))/$@'
else
object_label_flags = '-D__OBJECT_LABEL__=$(subst /,$$,$(subst -,_,$(subst $(BASEDIR)/,,$(CURDIR))/$@))'
endif
c_flags += $(object_label_flags) $(CFLAGS-stack-boundary)
a_flags += $(object_label_flags) $(CFLAGS-stack-boundary)
