obj-y += coverage.o
ifneq ($(CONFIG_CC_IS_CLANG),y)
obj-y += gcov_base.o gcov.o
obj-y += $(call cc-ifversion,-lt,0407, \
		gcc_3_4.o, $(call cc-ifversion,-lt,0409, \
		gcc_4_7.o, $(call cc-ifversion,-lt,0500, \
		gcc_4_9.o, $(call cc-ifversion,-lt,0700, \
		gcc_5.o, gcc_7.o))))
else
obj-y += llvm.o
endif
