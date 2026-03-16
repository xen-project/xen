obj-y += coverage.o
ifneq ($(CONFIG_CC_IS_CLANG),y)
obj-y += gcov_base.o gcov.o
obj-y += gcc_4_7.o
else
obj-y += llvm.o
endif
