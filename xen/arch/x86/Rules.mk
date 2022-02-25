########################################
# x86-specific definitions

ifneq ($(filter -DHAVE_AS_QUOTED_SYM,$(XEN_CFLAGS)),)
object_label_flags = '-D__OBJECT_LABEL__=$@'
else
object_label_flags = '-D__OBJECT_LABEL__=$(subst /,$$,$(subst -,_,$@))'
endif
c_flags += $(object_label_flags) $(CFLAGS_stack_boundary)
a_flags += $(object_label_flags) $(CFLAGS_stack_boundary)
