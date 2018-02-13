obj-y += coverage.o
ifneq ($(clang),y)
obj-y += gcov_base.o gcov.o
obj-y += $(call cc-ifversion,lt,0x040700, \
		gcc_3_4.o, $(call cc-ifversion,lt,0x040900, \
		gcc_4_7.o, $(call cc-ifversion,lt,0x050000, \
		gcc_4_9.o, $(call cc-ifversion,lt,0x070000, \
		gcc_5.o, gcc_7.o))))
else
obj-y += llvm.o
endif
